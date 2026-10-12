"""Operator-configurable SMS: method, phone parameter, message parameter.

SMS brokers disagree about almost everything -- some want a GET with query
parameters, some a form POST, some JSON -- so the channel exposes the method and
both parameter names. The constraint running through these tests is that a
channel configured before any of this existed must keep sending exactly the
request it always sent.
"""
from __future__ import annotations

import json
import pathlib
import re
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from myownca.comms import (
    ChannelConfig,
    CommsConfigError,
    CommsError,
    Message,
    NotificationChannel,
)
from myownca.comms.sms import send_sms

SENT = "myownca.comms.sms.http_send"
URL = "https://sms.example.test/send"


def _config(**config) -> ChannelConfig:
    config.setdefault("url", URL)
    secrets = config.pop("secrets", {})
    return ChannelConfig(
        channel=NotificationChannel.SMS, enabled=True, config=config, secrets=secrets
    )


def _send(channel_config: ChannelConfig, *, body: str = "Your certificate is ready"):
    with mock.patch(SENT, return_value=(200, "queued")) as sent:
        result = send_sms(channel_config, "+15551234567", Message(body=body))
    self_args, self_kwargs = sent.call_args
    return result, self_args, self_kwargs


class BackwardCompatibilityTests(unittest.TestCase):
    """The upgrade must be invisible to a channel already in service."""

    def test_a_channel_with_no_new_options_sends_the_original_request(self) -> None:
        _, args, kwargs = _send(_config())

        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], URL)
        self.assertEqual(
            json.loads(kwargs["data"].decode()),
            {"to": "+15551234567", "message": "Your certificate is ready"},
        )
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")

    def test_an_existing_body_template_still_wins(self) -> None:
        _, args, kwargs = _send(
            _config(body_template='{"msisdn":"{recipient}","text":"{body}"}')
        )

        self.assertEqual(args[0], "POST")
        self.assertEqual(
            json.loads(kwargs["data"].decode()),
            {"msisdn": "+15551234567", "text": "Your certificate is ready"},
        )

    def test_a_template_that_does_not_render_json_is_still_rejected(self) -> None:
        with self.assertRaises(CommsConfigError):
            _send(_config(body_template="to={recipient}"))


class MethodTests(unittest.TestCase):
    def test_get_puts_both_parameters_in_the_query_string(self) -> None:
        _, args, kwargs = _send(
            _config(method="GET", recipient_param="msisdn", message_param="text")
        )

        self.assertEqual(args[0], "GET")
        self.assertIsNone(kwargs["data"])
        query = parse_qs(urlsplit(args[1]).query)
        self.assertEqual(query["msisdn"], ["+15551234567"])
        self.assertEqual(query["text"], ["Your certificate is ready"])

    def test_get_keeps_a_query_the_broker_url_already_carries(self) -> None:
        """An API key in the URL must survive, not be replaced by our parameters."""
        _, args, _ = _send(
            _config(url=f"{URL}?apikey=abc123", method="GET", recipient_param="msisdn")
        )

        query = parse_qs(urlsplit(args[1]).query)
        self.assertEqual(query["apikey"], ["abc123"])
        self.assertEqual(query["msisdn"], ["+15551234567"])

    def test_put_sends_the_parameters_in_the_body(self) -> None:
        _, args, kwargs = _send(
            _config(method="PUT", recipient_param="msisdn", message_param="text")
        )

        self.assertEqual(args[0], "PUT")
        self.assertEqual(
            json.loads(kwargs["data"].decode()),
            {"msisdn": "+15551234567", "text": "Your certificate is ready"},
        )

    def test_the_method_is_case_insensitive(self) -> None:
        _, args, _ = _send(_config(method="get"))
        self.assertEqual(args[0], "GET")

    def test_an_unsupported_method_is_refused(self) -> None:
        with self.assertRaises(CommsConfigError) as caught:
            _send(_config(method="DELETE"))
        self.assertIn("DELETE", str(caught.exception))

    def test_a_body_template_with_get_is_refused_rather_than_ignored(self) -> None:
        """Silently dropping the template would send the default parameters
        instead -- the wrong payload, with no indication anything was wrong."""
        with self.assertRaises(CommsConfigError) as caught:
            _send(_config(method="GET", body_template='{"to":"{recipient}"}'))
        self.assertIn("GET", str(caught.exception))


class ParameterNameTests(unittest.TestCase):
    def test_parameter_names_are_configurable(self) -> None:
        _, _, kwargs = _send(_config(recipient_param="destination", message_param="content"))

        self.assertEqual(
            json.loads(kwargs["data"].decode()),
            {"destination": "+15551234567", "content": "Your certificate is ready"},
        )

    def test_blank_parameter_names_fall_back_to_the_defaults(self) -> None:
        _, _, kwargs = _send(_config(recipient_param="  ", message_param=""))

        self.assertEqual(
            set(json.loads(kwargs["data"].decode())), {"to", "message"}
        )

    def test_identical_parameter_names_are_refused(self) -> None:
        """One would overwrite the other, sending a message addressed to itself."""
        with self.assertRaises(CommsConfigError) as caught:
            _send(_config(recipient_param="text", message_param="text"))
        self.assertIn("differ", str(caught.exception))


class EncodingTests(unittest.TestCase):
    def test_form_encoding_is_used_when_the_operator_asks_for_it(self) -> None:
        _, _, kwargs = _send(
            _config(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                recipient_param="msisdn",
                message_param="text",
            )
        )

        self.assertEqual(
            parse_qs(kwargs["data"].decode()),
            {"msisdn": ["+15551234567"], "text": ["Your certificate is ready"]},
        )

    def test_form_encoding_is_detected_despite_a_charset_and_casing(self) -> None:
        _, _, kwargs = _send(
            _config(headers={"content-type": "Application/X-WWW-Form-Urlencoded; charset=UTF-8"})
        )

        self.assertEqual(parse_qs(kwargs["data"].decode())["to"], ["+15551234567"])

    def test_json_remains_the_default_encoding(self) -> None:
        _, _, kwargs = _send(_config())
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")

    def test_values_needing_escaping_survive_each_encoding(self) -> None:
        tricky = 'Ready: "CN=a&b" — 100%'
        _, _, json_kwargs = _send(_config(), body=tricky)
        self.assertEqual(json.loads(json_kwargs["data"].decode())["message"], tricky)

        _, _, form_kwargs = _send(
            _config(headers={"Content-Type": _FORM}), body=tricky
        )
        self.assertEqual(parse_qs(form_kwargs["data"].decode())["message"], [tricky])

        _, get_args, _ = _send(_config(method="GET"), body=tricky)
        self.assertEqual(parse_qs(urlsplit(get_args[1]).query)["message"], [tricky])


_FORM = "application/x-www-form-urlencoded"


class UnchangedBehaviourTests(unittest.TestCase):
    def test_a_bearer_token_is_still_sent_as_a_header(self) -> None:
        _, _, kwargs = _send(_config(secrets={"bearer_token": "sms-secret"}))
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sms-secret")

    def test_the_token_never_reaches_the_query_string(self) -> None:
        """Secrets in a URL end up in broker access logs."""
        _, args, _ = _send(_config(method="GET", secrets={"bearer_token": "sms-secret"}))
        self.assertNotIn("sms-secret", args[1])

    def test_a_missing_url_is_refused(self) -> None:
        with self.assertRaises(CommsConfigError):
            _send(_config(url=""))

    def test_a_missing_recipient_is_refused(self) -> None:
        with self.assertRaises(CommsError):
            with mock.patch(SENT, return_value=(200, "")):
                send_sms(_config(), "", Message(body="x"))

    def test_a_broker_failure_is_reported_not_raised(self) -> None:
        with mock.patch(SENT, return_value=(502, "gateway down")):
            result = send_sms(_config(), "+15551234567", Message(body="x"))
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 502)


class ExtraParameterTests(unittest.TestCase):
    """Real brokers need account, sender and message-type fields alongside the
    message. Without these the channel could only ever send two parameters."""

    def test_static_parameters_ride_along_in_a_form_post(self) -> None:
        """The mobitex.pl shape: curl -d user -d pass -d type -d number -d from -d text."""
        result, args, kwargs = _send(
            _config(
                method="POST",
                headers={"Content-Type": _FORM},
                recipient_param="number",
                message_param="text",
                extra_params={
                    "user": "landi2",
                    "pass": "{password}",
                    "type": "sms",
                    "from": "SC2labs",
                },
                secrets={"password": "broker-secret"},
            )
        )

        self.assertEqual(args[0], "POST")
        self.assertEqual(
            parse_qs(kwargs["data"].decode()),
            {
                "user": ["landi2"],
                "pass": ["broker-secret"],
                "type": ["sms"],
                "from": ["SC2labs"],
                "number": ["+15551234567"],
                "text": ["Your certificate is ready"],
            },
        )
        self.assertTrue(result.success)

    def test_static_parameters_also_ride_along_in_a_get(self) -> None:
        _, args, _ = _send(
            _config(method="GET", extra_params={"user": "landi2", "type": "sms"})
        )

        query = parse_qs(urlsplit(args[1]).query)
        self.assertEqual(query["user"], ["landi2"])
        self.assertEqual(query["type"], ["sms"])
        self.assertEqual(query["to"], ["+15551234567"])

    def test_a_broker_credential_is_read_from_the_encrypted_secret(self) -> None:
        """config_json is stored in cleartext; secrets are encrypted. A password
        must be referenced, never typed into the parameter value."""
        _, _, kwargs = _send(
            _config(
                headers={"Content-Type": _FORM},
                extra_params={"pass": "{password}"},
                secrets={"password": "broker-secret"},
            )
        )
        self.assertEqual(parse_qs(kwargs["data"].decode())["pass"], ["broker-secret"])

    def test_a_bearer_token_can_also_be_placed_in_a_parameter(self) -> None:
        _, _, kwargs = _send(
            _config(
                headers={"Content-Type": _FORM},
                extra_params={"apikey": "{bearer_token}"},
                secrets={"bearer_token": "tok-1"},
            )
        )
        self.assertEqual(parse_qs(kwargs["data"].decode())["apikey"], ["tok-1"])

    def test_referencing_a_secret_that_is_not_set_is_refused(self) -> None:
        """Sending an empty password would fail at the broker with a useless error."""
        with self.assertRaises(CommsConfigError) as caught:
            _send(_config(extra_params={"pass": "{password}"}))
        self.assertIn("password", str(caught.exception))

    def test_a_static_parameter_cannot_shadow_the_phone_or_message(self) -> None:
        with self.assertRaises(CommsConfigError) as caught:
            _send(_config(recipient_param="number", extra_params={"number": "000"}))
        self.assertIn("collides", str(caught.exception))

    def test_an_unnamed_parameter_is_refused(self) -> None:
        with self.assertRaises(CommsConfigError):
            _send(_config(extra_params={"   ": "value"}))

    def test_a_non_mapping_is_refused(self) -> None:
        with self.assertRaises(CommsConfigError):
            _send(_config(extra_params="user=landi2"))

    def test_a_channel_without_extra_parameters_is_unaffected(self) -> None:
        _, _, kwargs = _send(_config())
        self.assertEqual(
            json.loads(kwargs["data"].decode()),
            {"to": "+15551234567", "message": "Your certificate is ready"},
        )


class SecretsInHeadersTests(unittest.TestCase):
    """Some brokers authenticate with a header rather than a request field."""

    def test_a_header_value_can_reference_the_encrypted_password(self) -> None:
        _, _, kwargs = _send(
            _config(headers={"X-Api-Key": "{password}"}, secrets={"password": "hdr-secret"})
        )
        self.assertEqual(kwargs["headers"]["X-Api-Key"], "hdr-secret")

    def test_a_header_value_can_reference_the_bearer_token(self) -> None:
        _, _, kwargs = _send(
            _config(
                headers={"Authorization": "Basic {bearer_token}"},
                secrets={"bearer_token": "tok-1"},
            )
        )
        self.assertEqual(kwargs["headers"]["Authorization"], "Basic tok-1")

    def test_a_header_referencing_an_unset_secret_is_refused(self) -> None:
        """Sending an empty credential would fail at the broker uninformatively."""
        with self.assertRaises(CommsConfigError):
            _send(_config(headers={"X-Api-Key": "{password}"}))

    def test_ordinary_headers_are_untouched(self) -> None:
        _, _, kwargs = _send(_config(headers={"X-Trace": "abc-123"}))
        self.assertEqual(kwargs["headers"]["X-Trace"], "abc-123")


class ChannelSetupHelpTests(unittest.TestCase):
    """The setup form carries the guidance these traps needed."""

    def _asset(self, name: str) -> str:
        import myownca.online.app as app_module

        return (pathlib.Path(app_module.__file__).parent / "static" / name).read_text()

    def test_sms_offers_parameter_and_header_help(self) -> None:
        script = self._asset("admin.js")
        page = self._asset("admin.html")
        self.assertIn("tpl-sms-params-help", script)
        self.assertIn("tpl-sms-headers-help", script)
        self.assertIn('<template id="tpl-sms-params-help">', page)
        self.assertIn('<template id="tpl-sms-headers-help">', page)

    def test_slack_help_lists_every_scope_the_channel_uses(self) -> None:
        """The docstring omitted im:write, which is why fixing users:read.email
        only surfaced the next missing_scope."""
        page = self._asset("admin.html")
        block = page.split('<template id="tpl-slack-scopes-help">', 1)[1].split("</template>", 1)[0]
        for scope in ("chat:write", "im:write", "users:read", "users:read.email"):
            self.assertIn(scope, block)
        self.assertIn("einstall", block)  # reinstall is mandatory after a scope change

    def test_the_slack_channel_documents_the_same_scopes(self) -> None:
        from myownca.comms import slack

        for scope in ("chat:write", "im:write", "users:read", "users:read.email"):
            self.assertIn(scope, slack.send_slack.__doc__)

    def test_help_is_only_offered_where_it_applies(self) -> None:
        script = self._asset("admin.js")
        block = script.split("const CHANNEL_HELP = {", 1)[1].split("\n};", 1)[0]
        self.assertIn("sms:", block)
        self.assertIn("slack:", block)
        self.assertNotIn("webhook:", block)


class AdminFormContractTests(unittest.TestCase):
    """The form writes config keys straight through, so a rename in one place
    and not the other silently produces a channel that ignores its settings."""

    def _admin_js(self) -> str:
        import myownca.online.app as app_module

        return (pathlib.Path(app_module.__file__).parent / "static" / "admin.js").read_text()

    def _sms_schema(self) -> str:
        return self._admin_js().split("  sms: {", 1)[1].split("\n  },", 1)[0]

    def test_the_form_offers_the_three_configurable_options(self) -> None:
        schema = self._sms_schema()
        self.assertIn('name: "method"', schema)
        self.assertIn('name: "recipient_param"', schema)
        self.assertIn('name: "message_param"', schema)

    def test_the_method_choices_match_what_the_channel_accepts(self) -> None:
        from myownca.comms.sms import _VALID_METHODS

        schema = self._sms_schema()
        offered = set(
            re.findall(r'options: \[([^\]]+)\]', schema)[0].replace('"', "").split(", ")
        )
        self.assertEqual(offered, _VALID_METHODS)

    def test_the_form_offers_a_place_for_static_broker_parameters(self) -> None:
        """Their absence is what sent operators to the headers box, where
        colon-less lines were silently discarded."""
        schema = self._sms_schema()
        self.assertIn('name: "extra_params"', schema)
        self.assertIn('type: "params"', schema)

    def test_the_form_offers_an_encrypted_password_secret(self) -> None:
        from myownca.comms.service import _SECRET_KEYS
        from myownca.comms import NotificationChannel as Channel

        schema = self._sms_schema()
        self.assertIn('name: "password"', schema)
        self.assertIn("password", _SECRET_KEYS[Channel.SMS])

    def test_the_params_box_round_trips_and_refuses_malformed_lines(self) -> None:
        """A dropped credential line is exactly the failure being fixed."""
        script = self._admin_js()
        self.assertIn("function _textToParams", script)
        self.assertIn("function _paramsToText", script)
        self.assertIn("must be written as name=value", script)
        self.assertIn('if (type === "params")', script)

    def test_a_rejected_parameter_line_reaches_the_operator(self) -> None:
        """collectChannelPayload can now throw, so it must sit inside the try."""
        script = self._admin_js()
        save = script.split("configState.saving(", 1)[1].split("catch (error)", 1)[0]
        self.assertIn("collectChannelPayload(fieldsContainer)", save)

    def test_the_headers_label_says_it_is_not_for_broker_parameters(self) -> None:
        self.assertIn("not broker parameters", self._sms_schema())

    def test_the_placeholders_show_the_real_defaults(self) -> None:
        from myownca.comms.sms import _DEFAULT_MESSAGE_PARAM, _DEFAULT_RECIPIENT_PARAM

        schema = self._sms_schema()
        self.assertIn(f'placeholder: "{_DEFAULT_RECIPIENT_PARAM}"', schema)
        self.assertIn(f'placeholder: "{_DEFAULT_MESSAGE_PARAM}"', schema)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
