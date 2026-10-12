from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException
from starlette.requests import Request

from myownca.config import Settings
from myownca.setup.app import HSMPayload, create_setup_app
from myownca.setup.config_writer import read_config_env, read_secrets, write_secrets
from myownca.setup.orchestrator import SetupError, SetupOrchestrator
from myownca.setup.state import load_setup_state, save_setup_state
from myownca.setup.token import SetupAuth
from tests.helpers import route_endpoint


def _request(*, session: str, csrf: str | None = None) -> Request:
    headers = [(b"cookie", f"myownca_setup={session}".encode())]
    if csrf is not None:
        headers.append((b"x-csrf-token", csrf.encode()))
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers})


def _prepare_for_finalize(orchestrator: SetupOrchestrator) -> None:
    orchestrator.set_install_type("lab")
    orchestrator.set_listener(topology="proxy")
    orchestrator.set_admins(
        {"id": "admin-1", "email": "admin@example.test", "password": "p" * 16}
    )


def _test_current_cloud_config(orchestrator: SetupOrchestrator) -> None:
    current = dict(load_setup_state(orchestrator.state_dir).data["hsm"])
    backend = str(current.pop("backend"))
    orchestrator.test_hsm(
        backend,
        provider_test_hook=lambda _values: True,
        **current,
    )


def _finalize_with_configured_issuer(orchestrator: SetupOrchestrator) -> None:
    with (
        mock.patch("myownca.setup.orchestrator._require_cloud_sdk"),
        mock.patch(
            "myownca.setup.provisioning.SetupProvisioningService"
        ) as provisioning_type,
    ):
        provisioning = provisioning_type.return_value
        provisioning.status.return_value = {"configured": True, "pending": []}
        provisioning.assert_finalizable = mock.Mock(
            return_value={"configured": True, "pending": []}
        )
        orchestrator.finalize()


class CloudSettingsTests(unittest.TestCase):
    def test_cloud_defaults_keep_the_local_install_self_contained(self) -> None:
        settings = Settings.from_mapping({})
        self.assertEqual(settings.hsm_backend, "software")
        self.assertEqual(settings.service_key_backend, "software")
        self.assertEqual(settings.azure_key_protection, "hsm")
        for name in (
            "aws_region",
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
            "azure_vault_url",
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
        ):
            self.assertIsNone(getattr(settings, name), name)

    def test_cloud_settings_parse_the_public_and_secret_env_contract(self) -> None:
        settings = Settings.from_mapping(
            {
                "MYOWNCA_HSM_BACKEND": "AWS_KMS",
                "MYOWNCA_SERVICE_KEY_BACKEND": "AWS_KMS",
                "MYOWNCA_AWS_REGION": "eu-central-1",
                "MYOWNCA_AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
                "MYOWNCA_AWS_SECRET_ACCESS_KEY": "aws-secret",
                "MYOWNCA_AWS_SESSION_TOKEN": "aws-session",
                "MYOWNCA_AZURE_VAULT_URL": "https://ca.vault.azure.net",
                "MYOWNCA_AZURE_TENANT_ID": "tenant",
                "MYOWNCA_AZURE_CLIENT_ID": "client",
                "MYOWNCA_AZURE_CLIENT_SECRET": "azure-secret",
                "MYOWNCA_AZURE_KEY_PROTECTION": "STANDARD",
            }
        )
        self.assertEqual(settings.hsm_backend, "aws_kms")
        self.assertEqual(settings.service_key_backend, "aws_kms")
        self.assertEqual(settings.aws_region, "eu-central-1")
        self.assertEqual(settings.aws_access_key_id, "AKIAEXAMPLE")
        self.assertEqual(settings.aws_session_token, "aws-session")
        self.assertEqual(settings.azure_vault_url, "https://ca.vault.azure.net")
        self.assertEqual(settings.azure_client_secret, "azure-secret")
        self.assertEqual(settings.azure_key_protection, "standard")


class CloudOrchestratorTests(unittest.TestCase):
    def test_aws_snapshot_redacts_credentials_and_finalize_splits_files(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="AKIAEXAMPLE",
                aws_secret_access_key="aws-secret",
                aws_session_token="aws-session",
                service_key_backend="aws_kms",
            )
            snapshot = orchestrator.snapshot()
            serialized = json.dumps(snapshot)
            self.assertEqual(snapshot["hsm"]["backend"], "aws_kms")
            self.assertTrue(snapshot["hsm"]["credentials_configured"])
            self.assertNotIn("AKIAEXAMPLE", serialized)
            self.assertNotIn("aws-secret", serialized)
            self.assertNotIn("aws-session", serialized)

            _prepare_for_finalize(orchestrator)
            _test_current_cloud_config(orchestrator)
            _finalize_with_configured_issuer(orchestrator)
            config = read_config_env(tempdir)
            secrets = read_secrets(tempdir)
            loaded = Settings.load(tempdir, environ={})
            finalized_state = load_setup_state(tempdir)
            finalized_hsm_state = finalized_state.data["hsm"]

        self.assertEqual(config["MYOWNCA_HSM_BACKEND"], "aws_kms")
        self.assertEqual(config["MYOWNCA_AWS_REGION"], "eu-central-1")
        self.assertEqual(config["MYOWNCA_SERVICE_KEY_BACKEND"], "aws_kms")
        self.assertNotIn("MYOWNCA_AWS_ACCESS_KEY_ID", config)
        self.assertNotIn("MYOWNCA_AWS_SECRET_ACCESS_KEY", config)
        self.assertEqual(secrets["MYOWNCA_AWS_ACCESS_KEY_ID"], "AKIAEXAMPLE")
        self.assertEqual(secrets["MYOWNCA_AWS_SECRET_ACCESS_KEY"], "aws-secret")
        self.assertEqual(secrets["MYOWNCA_AWS_SESSION_TOKEN"], "aws-session")
        self.assertEqual(loaded.hsm_backend, "aws_kms")
        self.assertEqual(loaded.aws_secret_access_key, "aws-secret")
        self.assertNotIn("aws_access_key_id", finalized_hsm_state)
        self.assertNotIn("aws_secret_access_key", finalized_hsm_state)
        self.assertTrue(finalized_hsm_state["credentials_configured"])
        self.assertNotIn("cloud_hsm_test", finalized_state.data)

    def test_azure_snapshot_redacts_credentials_and_finalize_splits_files(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "azure_key_vault",
                azure_vault_url="https://ca.vault.azure.net",
                azure_tenant_id="tenant-id",
                azure_client_id="client-id",
                azure_client_secret="azure-secret",
                azure_key_protection="standard",
                service_key_backend="azure_key_vault",
            )
            snapshot = orchestrator.snapshot()
            serialized = json.dumps(snapshot)
            self.assertTrue(snapshot["hsm"]["credentials_configured"])
            self.assertNotIn("tenant-id", serialized)
            self.assertNotIn("client-id", serialized)
            self.assertNotIn("azure-secret", serialized)

            _prepare_for_finalize(orchestrator)
            _test_current_cloud_config(orchestrator)
            _finalize_with_configured_issuer(orchestrator)
            config = read_config_env(tempdir)
            secrets = read_secrets(tempdir)

        self.assertEqual(
            config["MYOWNCA_AZURE_VAULT_URL"], "https://ca.vault.azure.net"
        )
        self.assertEqual(config["MYOWNCA_AZURE_KEY_PROTECTION"], "standard")
        self.assertNotIn("MYOWNCA_AZURE_TENANT_ID", config)
        self.assertNotIn("MYOWNCA_AZURE_CLIENT_SECRET", config)
        self.assertEqual(secrets["MYOWNCA_AZURE_TENANT_ID"], "tenant-id")
        self.assertEqual(secrets["MYOWNCA_AZURE_CLIENT_ID"], "client-id")
        self.assertEqual(secrets["MYOWNCA_AZURE_CLIENT_SECRET"], "azure-secret")

    def test_local_finalize_writes_no_cloud_configuration_or_secrets(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm("software")
            _prepare_for_finalize(orchestrator)
            orchestrator.finalize()
            config = read_config_env(tempdir)
            secrets = read_secrets(tempdir)
        self.assertEqual(config["MYOWNCA_HSM_BACKEND"], "software")
        self.assertEqual(config["MYOWNCA_SERVICE_KEY_BACKEND"], "software")
        self.assertFalse(any("AWS" in key or "AZURE" in key for key in config))
        self.assertFalse(any("AWS" in key or "AZURE" in key for key in secrets))

    def test_cloud_finalize_requires_a_successful_test(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            _prepare_for_finalize(orchestrator)
            with self.assertRaises(SetupError) as caught:
                orchestrator.finalize()
        self.assertIn("Test the current cloud", str(caught.exception))

    def test_successful_cloud_test_marks_the_current_payload(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            self.assertFalse(orchestrator.snapshot()["hsm"]["connection_tested"])
            _test_current_cloud_config(orchestrator)
            self.assertTrue(orchestrator.snapshot()["hsm"]["connection_tested"])

            _prepare_for_finalize(orchestrator)
            _finalize_with_configured_issuer(orchestrator)
            self.assertTrue(orchestrator.snapshot()["complete"])

    def test_changing_cloud_payload_invalidates_successful_test(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            _test_current_cloud_config(orchestrator)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-west-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            self.assertFalse(orchestrator.snapshot()["hsm"]["connection_tested"])
            _prepare_for_finalize(orchestrator)
            with self.assertRaises(SetupError):
                orchestrator.finalize()

    def test_resubmitting_the_tested_payload_preserves_success_marker(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
                service_key_backend="aws_kms",
            )
            _test_current_cloud_config(orchestrator)
            # This is the same POST /setup/hsm performed by submitConfigSteps.
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
                service_key_backend="aws_kms",
            )
            self.assertTrue(orchestrator.snapshot()["hsm"]["connection_tested"])

    def test_failed_retest_does_not_mark_changed_payload(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            _test_current_cloud_config(orchestrator)
            with self.assertRaises(SetupError):
                orchestrator.test_hsm(
                    "aws_kms",
                    aws_region="eu-west-1",
                    aws_access_key_id="new-key",
                    aws_secret_access_key="new-secret",
                    provider_test_hook=lambda _values: False,
                )
            # The failed candidate was never made current, but attempting a new
            # probe still invalidates the stale success marker.
            self.assertFalse(orchestrator.snapshot()["hsm"]["connection_tested"])

    def test_azure_vault_url_is_canonicalized_like_the_adapter(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "azure_key_vault",
                azure_vault_url="HTTPS://CA.VAULT.AZURE.NET/",
                azure_tenant_id="tenant",
                azure_client_id="client",
                azure_client_secret="secret",
            )
            self.assertEqual(
                orchestrator.snapshot()["hsm"]["azure_vault_url"],
                "https://ca.vault.azure.net",
            )

    def test_azure_vault_url_rejects_paths_credentials_query_and_fragment(self) -> None:
        invalid_urls = (
            "http://ca.vault.azure.net",
            "https://user@ca.vault.azure.net",
            "https://user:password@ca.vault.azure.net",
            "https://ca.vault.azure.net/keys",
            "https://ca.vault.azure.net?api-version=1",
            "https://ca.vault.azure.net#fragment",
        )
        for vault_url in invalid_urls:
            with self.subTest(vault_url=vault_url), TemporaryDirectory() as tempdir:
                with self.assertRaises(SetupError) as caught:
                    SetupOrchestrator(tempdir).set_hsm(
                        "azure_key_vault",
                        azure_vault_url=vault_url,
                        azure_tenant_id="tenant",
                        azure_client_id="client",
                        azure_client_secret="secret",
                    )
                self.assertIn("HTTPS origin without a path or credentials", str(caught.exception))

    def test_cloud_provider_requires_its_complete_configuration(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError) as caught:
                SetupOrchestrator(tempdir).set_hsm(
                    "aws_kms", aws_region="eu-central-1"
                )
        self.assertIn("AWS access key ID", str(caught.exception))
        self.assertIn("AWS secret access key", str(caught.exception))

    def test_service_keys_cannot_target_a_different_cloud(self) -> None:
        with TemporaryDirectory() as tempdir:
            with self.assertRaises(SetupError):
                SetupOrchestrator(tempdir).set_hsm(
                    "aws_kms",
                    aws_region="eu-central-1",
                    aws_access_key_id="key",
                    aws_secret_access_key="secret",
                    service_key_backend="azure_key_vault",
                )

    def test_blank_credentials_keep_saved_values_when_resuming(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
            )
            orchestrator.set_hsm("aws_kms", aws_region="eu-west-1")
            tested: dict[str, str] = {}
            orchestrator.test_hsm(
                "aws_kms",
                aws_region="eu-west-1",
                provider_test_hook=tested.update,
            )
            self.assertTrue(orchestrator.snapshot()["hsm"]["credentials_configured"])
            self.assertEqual(tested["aws_access_key_id"], "key")
            self.assertEqual(tested["aws_secret_access_key"], "secret")

    def test_new_aws_primary_credentials_clear_an_old_session_token(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="temporary-key",
                aws_secret_access_key="temporary-secret",
                aws_session_token="old-session",
            )
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="long-lived-key",
                aws_secret_access_key="long-lived-secret",
            )
            _prepare_for_finalize(orchestrator)
            _test_current_cloud_config(orchestrator)
            _finalize_with_configured_issuer(orchestrator)
            secrets = read_secrets(tempdir)
        self.assertEqual(secrets["MYOWNCA_AWS_ACCESS_KEY_ID"], "long-lived-key")
        self.assertNotIn("MYOWNCA_AWS_SESSION_TOKEN", secrets)

    def test_resume_after_finalize_state_scrub_reads_credentials_from_secrets(self) -> None:
        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.set_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key-from-secrets",
                aws_secret_access_key="secret-from-secrets",
            )
            write_secrets(
                tempdir,
                {
                    "MYOWNCA_AWS_ACCESS_KEY_ID": "key-from-secrets",
                    "MYOWNCA_AWS_SECRET_ACCESS_KEY": "secret-from-secrets",
                },
            )
            # Simulate a crash after finalize saved its scrubbed state but
            # before it wrote the completion latch.
            state = load_setup_state(tempdir)
            state.data["hsm"] = orchestrator.snapshot()["hsm"]
            save_setup_state(tempdir, state)

            tested: dict[str, str] = {}
            orchestrator.test_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                provider_test_hook=tested.update,
            )
        self.assertEqual(tested["aws_access_key_id"], "key-from-secrets")
        self.assertEqual(tested["aws_secret_access_key"], "secret-from-secrets")

    def test_cloud_check_reports_a_missing_optional_sdk(self) -> None:
        from myownca.ca_hsm.remote import CloudBackendUnavailable

        with TemporaryDirectory() as tempdir:
            orchestrator = SetupOrchestrator(tempdir)
            with mock.patch(
                "myownca.ca_hsm.aws_kms.AWSKMSHSM",
                side_effect=CloudBackendUnavailable(
                    "AWS KMS",
                    "load SDK",
                    code="SDK_NOT_INSTALLED",
                    detail='install myownca with the "aws-kms" extra',
                ),
            ), self.assertRaises(SetupError) as caught:
                orchestrator.test_hsm(
                    "aws_kms",
                    aws_region="eu-central-1",
                    aws_access_key_id="key",
                    aws_secret_access_key="secret",
                )
        self.assertIn("SDK_NOT_INSTALLED", str(caught.exception))
        self.assertIn("aws-kms", str(caught.exception))

    def test_default_aws_check_builds_adapter_and_tests_connection(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch(
            "myownca.ca_hsm.aws_kms.AWSKMSHSM"
        ) as factory:
            SetupOrchestrator(tempdir).test_hsm(
                "aws_kms",
                aws_region="eu-central-1",
                aws_access_key_id="key",
                aws_secret_access_key="secret",
                aws_session_token="session",
            )
        factory.assert_called_once_with(
            region_name="eu-central-1",
            aws_access_key_id="key",
            aws_secret_access_key="secret",
            aws_session_token="session",
        )
        factory.return_value.test_connection.assert_called_once_with()

    def test_default_azure_check_builds_adapter_and_tests_connection(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch(
            "myownca.ca_hsm.azure_key_vault.AzureKeyVaultHSM"
        ) as factory:
            SetupOrchestrator(tempdir).test_hsm(
                "azure_key_vault",
                azure_vault_url="https://ca.vault.azure.net",
                azure_tenant_id="tenant",
                azure_client_id="client",
                azure_client_secret="secret",
                azure_key_protection="standard",
            )
        factory.assert_called_once_with(
            vault_url="https://ca.vault.azure.net",
            tenant_id="tenant",
            client_id="client",
            client_secret="secret",
            key_protection="standard",
        )
        factory.return_value.test_connection.assert_called_once_with()

    def test_local_checks_do_not_enter_the_cloud_probe(self) -> None:
        with TemporaryDirectory() as tempdir, mock.patch(
            "myownca.setup.orchestrator._test_cloud_provider_connection"
        ) as cloud_probe:
            orchestrator = SetupOrchestrator(tempdir)
            orchestrator.test_hsm("software")
            module = Path(tempdir) / "opensc.so"
            module.write_text("fake")
            orchestrator.test_hsm("pkcs11", pkcs11_lib=str(module))
        cloud_probe.assert_not_called()


class CloudSetupEndpointTests(unittest.TestCase):
    def test_test_endpoint_uses_hook_without_reflecting_credentials(self) -> None:
        captured: list[dict[str, str]] = []
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session, csrf = auth.open_session()
            app.state.cloud_provider_test_hook = lambda values: captured.append(values)
            result = route_endpoint(app, "/setup/hsm/test", "POST")(
                HSMPayload(
                    backend="aws_kms",
                    aws_region="eu-central-1",
                    aws_access_key_id="key",
                    aws_secret_access_key="secret",
                ),
                _request(session=session, csrf=csrf),
            )
            tested_snapshot = app.state.orchestrator.snapshot()
        self.assertEqual(result, {"ok": True, "backend": "aws_kms"})
        self.assertEqual(captured[0]["aws_secret_access_key"], "secret")
        self.assertNotIn("secret", json.dumps(result))
        self.assertTrue(tested_snapshot["hsm"]["connection_tested"])

    def test_test_endpoint_redacts_arbitrary_provider_error_text(self) -> None:
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session, csrf = auth.open_session()

            def fail(_values):
                raise RuntimeError("provider echoed secret-value")

            app.state.cloud_provider_test_hook = fail
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/hsm/test", "POST")(
                    HSMPayload(
                        backend="aws_kms",
                        aws_region="eu-central-1",
                        aws_access_key_id="key",
                        aws_secret_access_key="secret-value",
                    ),
                    _request(session=session, csrf=csrf),
                )
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("RuntimeError", caught.exception.detail)
        self.assertNotIn("secret-value", caught.exception.detail)

    def test_test_endpoint_requires_csrf(self) -> None:
        with TemporaryDirectory() as tempdir:
            auth = SetupAuth()
            app = create_setup_app(tempdir, auth)
            session, _ = auth.open_session()
            with self.assertRaises(HTTPException) as caught:
                route_endpoint(app, "/setup/hsm/test", "POST")(
                    HSMPayload(
                        backend="aws_kms",
                        aws_region="eu-central-1",
                        aws_access_key_id="key",
                        aws_secret_access_key="secret",
                    ),
                    _request(session=session),
                )
        self.assertEqual(caught.exception.status_code, 403)


class CloudSetupMarkupTests(unittest.TestCase):
    def test_cloud_choices_include_provider_access_helpers(self) -> None:
        html = (
            Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()

        self.assertIn('id="aws-kms-helper"', html)
        self.assertIn('id="aws-kms-bootstrap-policy"', html)
        self.assertIn('id="aws-kms-runtime-policy"', html)
        self.assertIn('"kms:CreateKey"', html)
        self.assertIn('"kms:TagResource"', html)
        self.assertIn(
            '"Resource": "arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT_ID:key/KEY_ID"',
            html,
        )
        self.assertIn('id="azure-key-vault-helper"', html)
        self.assertIn("Application (client) ID", html)
        self.assertIn("Directory (tenant) ID", html)
        self.assertIn("Key Vault Crypto Officer", html)
        self.assertIn("Review + assign", html)
        for policy_id in ("aws-kms-bootstrap-policy", "aws-kms-runtime-policy"):
            start = html.index(f'<pre id="{policy_id}">') + len(
                f'<pre id="{policy_id}">'
            )
            policy = json.loads(html[start : html.index("</pre>", start)])
            self.assertEqual(policy["Version"], "2012-10-17")

    def test_cloud_choices_are_optional_and_software_stays_selected(self) -> None:
        html = (
            Path(__file__).parents[1] / "src/myownca/setup/static/setup.html"
        ).read_text()
        self.assertIn('name="key-storage-location" value="local" checked', html)
        self.assertIn('name="local-hsm-backend" value="software" checked', html)
        self.assertIn('name="local-hsm-backend" value="pkcs11"', html)
        self.assertIn('name="cloud-hsm-backend" value="aws_kms"', html)
        self.assertIn('name="cloud-hsm-backend" value="azure_key_vault"', html)
        self.assertIn("This choice applies only to the Issuing Sub CA signing key.", html)
        self.assertIn("server-generated leaf keys are kept encrypted locally", html)
        self.assertIn('data-production-only title="Available for Production setup only."', html)
        self.assertIn("if (lab)", html)
        self.assertIn("updateInstallTypeFields();", html)
        self.assertIn('id="aws-kms-fields" class="cloud-fields hidden"', html)
        self.assertIn('id="azure-key-vault-fields" class="cloud-fields hidden"', html)
        self.assertIn('id="hsm-test-button"', html)
        self.assertIn("Local software mode needs no AWS or Azure configuration.", html)
        self.assertIn("<strong>New HSM</strong>", html)
        self.assertNotIn("<strong>New HSM and new DKEK</strong>", html)
        self.assertIn('id="pkcs11-dkek-choice" class="pkcs11-mode-section hidden"', html)
        self.assertIn('name="pkcs11-dkek-migration" value="shares" checked', html)
        self.assertIn('name="pkcs11-dkek-migration" value="disabled"', html)
        self.assertIn('id="pkcs11-new-dkek-count"', html)
        self.assertIn('id="pkcs11-recovery-dkek-count"', html)
        self.assertIn('min="1" max="255" step="any"', html)
        self.assertIn("function normalizeDkekShareCount(input)", html)
        self.assertIn("Math.min(255, Math.max(1, Math.round(value)))", html)
        self.assertIn('dkek_shares: selectedPkcs11DkekShares()', html)
        self.assertIn(
            '$("pkcs11-new-share-step").classList.toggle("hidden", !createsShares)',
            html,
        )
        self.assertIn(
            '$("pkcs11-import-step").classList.toggle("hidden", mode === "existing" || disablesDkek)',
            html,
        )
        self.assertIn('newDkekCount.value = "0"', html)
        self.assertIn('newDkekCount.dataset.enabledValue || "2"', html)
        self.assertIn("newDkekCount.disabled = !createsShares", html)
        self.assertIn('"Step 1 of 1"', html)
        self.assertIn('"Step 1 of 2"', html)
        self.assertIn('id="pkcs11-share-rows" class="pkcs11-share-rows"', html)
        self.assertIn("function renderPkcs11ShareRows(count)", html)
        self.assertIn("function collectPkcs11ShareSpecs(expectedCount)", html)
        self.assertIn("`dkek-share-${number}.pbe`", html)
        self.assertIn("Every DKEK share must use a different password.", html)
        self.assertIn("Do not keep these shares together.", html)
        self.assertIn("Delete the combined ZIP after distribution.", html)
        self.assertIn('link.download = "dkek-shares.zip"', html)
        self.assertIn("shares,", html)
        self.assertNotIn('id="pkcs11-share-filename"', html)
        self.assertNotIn('id="pkcs11-share-password"', html)
        self.assertIn("let cloudHsmTested = false;", html)
        self.assertIn("function invalidateCloudHsmTest()", html)
        self.assertIn("cloudHsmSelected() && !cloudHsmTested", html)
        self.assertIn('id="issuer-reset-panel" class="issuer-reset-panel hidden" open', html)
        self.assertIn('id="issuer-reset-pin-field" class="hidden"', html)
        self.assertIn("function updateIssuerResetPinVisibility()", html)
        self.assertIn("issuer-foundation-locked", html)
        self.assertIn("Reset the issuer step to remove the current Sub CA before changing this setting.", html)


if __name__ == "__main__":
    unittest.main()
