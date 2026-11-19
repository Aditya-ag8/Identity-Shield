"""Minimal AWS fakes for offline tests.

Not a botocore stub: the census code only calls list/describe/get operations and
paginates through them, so a dict of canned pages exercises the same code path
with far less ceremony. Error injection is a callable that raises.
"""

from __future__ import annotations

from typing import Any, Callable


class FakeClient:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append((name, kwargs))
            return self._respond(name, kwargs)

        return call

    def _respond(self, operation: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        if operation not in self._responses:
            raise AssertionError(f"unexpected call {operation}({kwargs})")
        value = self._responses[operation]
        if callable(value):
            return value(kwargs)
        return value

    def get_paginator(self, operation: str):
        pages = self._responses.get(operation)
        if pages is None:
            raise AssertionError(f"no paginator response for {operation}")
        if not isinstance(pages, list):
            raise AssertionError(f"paginator response for {operation} must be a list of pages")
        client = self

        class _Paginator:
            def paginate(self, **kwargs: Any):
                client.calls.append((operation, kwargs))
                yield from pages

        return _Paginator()


class FakeSession:
    """Session double. ``region_name`` is accepted to mimic GuardedSession."""

    def __init__(
        self,
        clients: dict[str, FakeClient],
        *,
        region: str = "eu-west-1",
        account_id: str = "123456789012",
        credentials: bool = True,
    ) -> None:
        self._clients = clients
        self.region = region
        self._account_id = account_id
        self._credentials = credentials

    def client(self, service: str, **_kwargs: Any) -> FakeClient:
        if service not in self._clients:
            raise AssertionError(f"no fake client for {service}")
        return self._clients[service]

    def raw_client(self, service: str, **_kwargs: Any) -> FakeClient:
        return self.client(service)

    def has_credentials(self) -> bool:
        return self._credentials

    def account_id(self) -> str:
        if not self._credentials:
            raise RuntimeError("no credentials")
        return self._account_id
