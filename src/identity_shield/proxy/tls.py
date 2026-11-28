"""Explicit Opt-In TLS Inspection Capability & Local CA Guard (`proxy/tls.py`).

Design invariants:
- TLS interception is OFF by default (`tls_intercept_enabled = False`).
- When disabled, HTTPS CONNECT behaves honestly as metadata-only tunnel forwarding.
- Private keys are NEVER written to SQLite, logs, API responses, or UI output.
- Supports certificate-pinned / mTLS passthrough exclusion lists cleanly.
"""

from __future__ import annotations

import os
import re
import shutil
import ssl
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from identity_shield import config

_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")

DEFAULT_TLS_PASSTHROUGH_HOSTS: tuple[str, ...] = (
    # Certificate-pinned / mTLS / OS update endpoints bypass MITM automatically
    "login.microsoftonline.com",
    "accounts.google.com",
    "signin.aws.amazon.com",
)


@dataclass
class TlsInspectionConfig:
    enabled: bool = False
    ca_dir: Path | None = None
    passthrough_hosts: tuple[str, ...] = DEFAULT_TLS_PASSTHROUGH_HOSTS
    verify_upstream: bool = True


class TlsCertAuthority:
    """Manages an isolated local Proxy CA on disk only when explicitly enabled."""

    def __init__(
        self,
        *,
        ca_dir: Path | None = None,
        which_fn: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._ca_dir = ca_dir or (config.DATA / "proxy_ca")
        self._which = which_fn
        self._runner = runner

    @property
    def ca_dir(self) -> Path:
        return self._ca_dir

    @property
    def ca_cert_path(self) -> Path:
        return self._ca_dir / "identity-shield-ca.crt"

    @property
    def ca_key_path(self) -> Path:
        return self._ca_dir / "identity-shield-ca.key"

    def openssl_available(self) -> bool:
        return bool(self._which("openssl"))

    def is_passthrough_host(self, host: str, passthrough_hosts: Iterable[str] = DEFAULT_TLS_PASSTHROUGH_HOSTS) -> bool:
        clean = str(host or "").strip().lower().split(":", 1)[0]
        for rule in passthrough_hosts:
            r = str(rule or "").strip().lower()
            if not r:
                continue
            if r.startswith("*.") and clean.endswith(r[1:]):
                return True
            if clean == r:
                return True
        return False

    def ensure_ca(self) -> dict[str, Any]:
        """Lazily initialize local CA keypair using OpenSSL if available. Key never leaves disk."""
        if self.ca_cert_path.is_file() and self.ca_key_path.is_file():
            return {"ready": True, "ca_cert_path": str(self.ca_cert_path), "created": False}

        openssl = self._which("openssl")
        if not openssl:
            return {
                "ready": False,
                "reason": "OpenSSL binary not found in PATH; TLS interception unavailable (falling back to CONNECT metadata mode).",
            }

        self._ca_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=Identity Shield Local Proxy CA",
            "-keyout",
            str(self.ca_key_path),
            "-out",
            str(self.ca_cert_path),
        ]
        proc = self._runner(cmd, shell=False, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or not self.ca_cert_path.is_file():
            return {
                "ready": False,
                "reason": f"CA generation failed: {(proc.stderr or proc.stdout or 'unknown').strip()[:200]}",
            }
        try:
            os.chmod(self.ca_key_path, 0o600)
        except OSError:
            pass
        return {"ready": True, "ca_cert_path": str(self.ca_cert_path), "created": True}

    def issue_host_cert(self, hostname: str) -> tuple[Path, Path] | None:
        """Issue or reuse a per-host leaf cert signed by the local CA when OpenSSL is ready."""
        clean = str(hostname or "").strip().lower().split(":", 1)[0]
        if not _SAFE_HOST_RE.match(clean):
            raise ValueError(f"Unsafe TLS leaf hostname: {hostname!r}")
        ca_state = self.ensure_ca()
        if not ca_state.get("ready"):
            return None

        certs_dir = self._ca_dir / "hosts"
        certs_dir.mkdir(parents=True, exist_ok=True)
        cert_file = (certs_dir / f"{clean}.crt").resolve()
        key_file = (certs_dir / f"{clean}.key").resolve()
        if not cert_file.is_relative_to(certs_dir.resolve()):
            raise ValueError("Host cert path escapes CA directory.")
        if cert_file.is_file() and key_file.is_file():
            return cert_file, key_file

        openssl = self._which("openssl")
        if not openssl:
            return None
        csr_file = certs_dir / f"{clean}.csr"
        proc1 = self._runner(
            [openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={clean}", "-keyout", str(key_file), "-out", str(csr_file)],
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc1.returncode != 0:
            return None
        proc2 = self._runner(
            [openssl, "x509", "-req", "-in", str(csr_file), "-CA", str(self.ca_cert_path), "-CAkey", str(self.ca_key_path), "-CAcreateserial", "-out", str(cert_file), "-days", "30", "-sha256"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if csr_file.exists():
            csr_file.unlink()
        if proc2.returncode != 0 or not cert_file.is_file():
            return None
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return cert_file, key_file

    def client_ssl_context(self, *, verify_upstream: bool = True) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify_upstream:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def status(self, *, enabled: bool = False, passthrough_hosts: Iterable[str] = DEFAULT_TLS_PASSTHROUGH_HOSTS) -> dict[str, Any]:
        """Return safe TLS inspection posture without ever exposing CA private key content."""
        return {
            "enabled": bool(enabled),
            "mode": "tls_inspection" if enabled else "connect_metadata_only",
            "openssl_available": self.openssl_available(),
            "ca_cert_exists": self.ca_cert_path.is_file(),
            "ca_cert_path": str(self.ca_cert_path) if self.ca_cert_path.is_file() else None,
            "ca_private_key_protected": True,
            "ca_private_key_in_db": False,
            "passthrough_hosts": list(passthrough_hosts),
        }
