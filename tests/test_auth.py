import json
from typing import Any, Dict, Optional

import pytest

from aw_client import ActivityWatchClient
from aw_client import client as client_module
from aw_client.config import load_server_api_key
from aw_client.desktop_session import DesktopSessionStore, SERVICE_NAME


class DummyResponse:
    def __init__(self, data: Optional[Dict[str, Any]] = None):
        self._data = data or {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Dict[str, Any]:
        return self._data


def test_desktop_session_store_is_the_single_credential_contract(monkeypatch):
    stored = {}
    monkeypatch.setattr(
        "aw_client.desktop_session.keyring.set_password",
        lambda service, target, value: stored.update(
            service=service, target=target, value=value
        ),
    )
    monkeypatch.setattr(
        "aw_client.desktop_session.keyring.get_password",
        lambda service, target: stored["value"],
    )

    store = DesktopSessionStore("AW.EXAMPLE.COM", "443")
    session = store.save(
        {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "access_expires_at": "2026-07-11T12:00:00+00:00",
        }
    )

    assert store.target == "aw.example.com:443"
    assert stored["service"] == SERVICE_NAME
    assert stored["target"] == store.target
    assert json.loads(stored["value"]) == {
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "access_expires_at": "2026-07-11T12:00:00+00:00",
    }
    assert store.load() == session


def test_desktop_session_store_rejects_incomplete_credentials(monkeypatch):
    monkeypatch.setattr(
        "aw_client.desktop_session.keyring.get_password",
        lambda _service, _target: '{"access_token":"only-access"}',
    )

    with pytest.raises(RuntimeError, match="incomplete"):
        DesktopSessionStore("aw.example.com", 443).load()


def test_client_sends_desktop_authorization_header(monkeypatch):
    monkeypatch.setattr(
        "aw_client.desktop_session.keyring.get_password",
        lambda _service, _target: (
            '{"access_token":"secret123","refresh_token":"refresh123",'
            '"access_expires_at":"2026-07-11T12:00:00+00:00"}'
        ),
    )
    monkeypatch.setattr(client_module, "SingleInstance", lambda name: object())
    captured = {}

    def fake_get(url, params=None, headers=None):
        captured["url"] = url
        captured["headers"] = headers
        return DummyResponse({"hostname": "test-host", "testing": False})

    monkeypatch.setattr(client_module.req, "get", fake_get)

    client = ActivityWatchClient(
        "test-client", host="aw.example.com", port=443, protocol="https"
    )
    assert client.get_info()["hostname"] == "test-host"
    assert captured["url"] == "https://aw.example.com:443/api/0/info"
    assert captured["headers"]["Authorization"] == "Bearer secret123"


def test_missing_desktop_session_has_no_parallel_auth_path(monkeypatch):
    monkeypatch.setattr(
        "aw_client.desktop_session.keyring.get_password",
        lambda _service, _target: None,
    )

    assert load_server_api_key("aw.example.com", 443) is None
