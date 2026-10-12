from __future__ import annotations

import os
import socket
import ssl
from datetime import datetime, timezone

_SYSLOG_TIMEOUT = 5
_APP_NAME = "myownca"
_VALID_PROTOCOLS = {"udp", "tcp", "tls"}


class SyslogForwarder:
    """Best-effort RFC 5424 syslog forwarder over UDP, TCP, or TCP+TLS.

    Forwarding never raises into the caller: a delivery failure must not break
    the action being audited (the database record is authoritative).
    """

    def __init__(self, host: str, port: int, protocol: str, facility: int) -> None:
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower()
        self.facility = int(facility)

    def emit(self, severity: int, msgid: str, message: str, *, occurred_at: datetime | None = None) -> bool:
        if self.protocol not in _VALID_PROTOCOLS or not self.host:
            return False
        frame = self._format(severity, msgid, message, occurred_at)
        try:
            if self.protocol == "udp":
                return self._send_udp(frame)
            return self._send_stream(frame, use_tls=self.protocol == "tls")
        except (OSError, ssl.SSLError):
            return False

    def _format(self, severity: int, msgid: str, message: str, occurred_at: datetime | None) -> bytes:
        pri = self.facility * 8 + (severity & 0x7)
        when = (occurred_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        timestamp = when.isoformat()
        hostname = socket.gethostname() or "-"
        procid = str(os.getpid())
        safe_msgid = (msgid or "-").replace(" ", "_")[:32]
        header = f"<{pri}>1 {timestamp} {hostname} {_APP_NAME} {procid} {safe_msgid} - "
        return (header + message).encode("utf-8")

    def _send_udp(self, frame: bytes) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SYSLOG_TIMEOUT)
            sock.sendto(frame, (self.host, self.port))
        return True

    def _send_stream(self, frame: bytes, *, use_tls: bool) -> bool:
        # RFC 6587 octet-counting framing for syslog over TCP.
        payload = f"{len(frame)} ".encode() + frame
        sock = socket.create_connection((self.host, self.port), timeout=_SYSLOG_TIMEOUT)
        try:
            if use_tls:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
            sock.sendall(payload)
        finally:
            sock.close()
        return True


def forwarder_from_config(config: dict[str, object]) -> SyslogForwarder | None:
    if not config.get("enabled") or not config.get("host"):
        return None
    return SyslogForwarder(
        host=str(config["host"]),
        port=int(config.get("port", 514)),
        protocol=str(config.get("protocol", "udp")),
        facility=int(config.get("facility", 13)),
    )
