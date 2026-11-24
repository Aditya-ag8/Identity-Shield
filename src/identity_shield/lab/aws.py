"""Read-only AWS access for the lab module.

The lab must be safe to inspect at any time, including while an attack is
running. Every AWS client used for census work is therefore wrapped in a guard
that refuses to call anything that could mutate state. This is a mechanical
check, not a convention: a typo like ``client.delete_bucket(...)`` raises before
the request is built.

Read operations are ``describe_*``, ``list_*``, ``get_*``, ``head_*``,
``lookup_*``, ``can_paginate`` and ``get_paginator``. Anything else is rejected.
"""

from __future__ import annotations

from typing import Any

MUTATING_PREFIXES = (
    "add_",
    "allocate_",
    "associate_",
    "attach_",
    "authorize_",
    "cancel_",
    "create_",
    "delete_",
    "deregister_",
    "detach_",
    "disable_",
    "disassociate_",
    "enable_",
    "import_",
    "modify_",
    "purchase_",
    "put_",
    "reboot_",
    "register_",
    "release_",
    "replace_",
    "reset_",
    "restore_",
    "revoke_",
    "run_",
    "set_",
    "start_",
    "stop_",
    "tag_",
    "terminate_",
    "untag_",
    "update_",
)


class ReadOnlyViolation(RuntimeError):
    """A mutating API call was attempted through the read-only guard."""


class GuardedClient:
    """Wraps a boto3 client and refuses mutating operations by name."""

    def __init__(self, client: Any, service: str) -> None:
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_service", service)

    def __getattr__(self, name: str) -> Any:
        if name.startswith(MUTATING_PREFIXES):
            raise ReadOnlyViolation(
                f"{self._service}.{name} is a mutating call; the lab census is read-only"
            )
        return getattr(self._client, name)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"GuardedClient({self._service})"


class LabSession:
    """Writable boto3 session for the runner.

    Deliberately separate from :class:`GuardedSession`: the census must never
    mutate the account, while an attack trial must be able to create and delete
    its own resources. Keeping them as different types means a census function
    cannot accidentally acquire a write-capable client.
    """

    def __init__(
        self,
        session: Any | None = None,
        region_name: str | None = None,
        profile_name: str | None = None,
    ) -> None:
        if session is None:
            import boto3

            session = boto3.Session(
                profile_name=profile_name, region_name=region_name
            )
        self._session = session
        self._region = region_name or getattr(session, "region_name", None)
        self._account_id: str | None = None

    @property
    def region(self) -> str | None:
        return self._region

    def client(self, service: str, **kwargs: Any) -> Any:
        if self._region and "region_name" not in kwargs:
            kwargs["region_name"] = self._region
        return self._session.client(service, **kwargs)

    def has_credentials(self) -> bool:
        try:
            return self._session.get_credentials() is not None
        except Exception:  # pragma: no cover - botocore edge cases
            return False

    def account_id(self) -> str:
        if self._account_id is None:
            identity = self.client("sts").get_caller_identity()
            self._account_id = str(identity["Account"])
        return self._account_id


class GuardedSession:
    """Lazy boto3 session that hands out guarded clients."""

    def __init__(self, session: Any | None = None, region_name: str | None = None, profile_name: str | None = None) -> None:
        if session is None:
            import boto3

            session = boto3.Session(profile_name=profile_name, region_name=region_name)
        self._session = session
        self._region = region_name or getattr(session, "region_name", None)
        self._account_id: str | None = None

    @property
    def region(self) -> str | None:
        return self._region

    def client(self, service: str, **kwargs: Any) -> GuardedClient:
        if self._region and "region_name" not in kwargs:
            kwargs["region_name"] = self._region
        return GuardedClient(self._session.client(service, **kwargs), service)

    def has_credentials(self) -> bool:
        try:
            return self._session.get_credentials() is not None
        except Exception:  # pragma: no cover - botocore edge cases
            return False

    def account_id(self) -> str:
        if self._account_id is None:
            identity = self.client("sts").get_caller_identity()
            self._account_id = str(identity["Account"])
        return self._account_id

    def raw_client(self, service: str, **kwargs: Any) -> Any:
        """Escape hatch for the doctor, which needs to probe Organizations.

        Kept separate and named so that every unguarded use is easy to find.
        """
        if self._region and "region_name" not in kwargs:
            kwargs["region_name"] = self._region
        return self._session.client(service, **kwargs)
