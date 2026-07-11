"""Shared Command OS desktop-session credential contract."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Union

import keyring


SERVICE_NAME = "CommandOS.ActivityWatch"


@dataclass(frozen=True)
class DesktopSession:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


class DesktopSessionStore:
    def __init__(self, host: str, port: Union[int, str]) -> None:
        normalized_host = str(host or "").strip().lower()
        if not normalized_host:
            raise ValueError("desktop session host is required")
        try:
            normalized_port = int(str(port))
        except (TypeError, ValueError) as exc:
            raise ValueError("desktop session port must be an integer") from exc
        if not 1 <= normalized_port <= 65535:
            raise ValueError("desktop session port must be between 1 and 65535")
        self._target = f"{normalized_host}:{normalized_port}"

    @property
    def target(self) -> str:
        return self._target

    def load(self) -> DesktopSession | None:
        value = keyring.get_password(SERVICE_NAME, self._target)
        if value is None:
            return None
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuntimeError("stored desktop session is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("stored desktop session must be an object")
        return _parse_session(payload)

    def save(self, payload: dict) -> DesktopSession:
        session = _parse_session(payload)
        keyring.set_password(
            SERVICE_NAME,
            self._target,
            json.dumps(
                {
                    "access_token": session.access_token,
                    "refresh_token": session.refresh_token,
                    "access_expires_at": session.access_expires_at.isoformat(),
                    "refresh_expires_at": session.refresh_expires_at.isoformat(),
                },
                separators=(",", ":"),
            ),
        )
        return session

    def delete(self) -> None:
        try:
            keyring.delete_password(SERVICE_NAME, self._target)
        except keyring.errors.PasswordDeleteError:
            return


def _parse_session(payload: dict) -> DesktopSession:
    access_token = str(payload.get("access_token") or "").strip()
    refresh_token = str(payload.get("refresh_token") or "").strip()
    access_expires_at_raw = str(payload.get("access_expires_at") or "").strip()
    refresh_expires_at_raw = str(payload.get("refresh_expires_at") or "").strip()
    if (
        not access_token
        or not refresh_token
        or not access_expires_at_raw
        or not refresh_expires_at_raw
    ):
        raise RuntimeError("stored desktop session is incomplete")
    try:
        access_expires_at = datetime.fromisoformat(
            access_expires_at_raw.replace("Z", "+00:00")
        )
        refresh_expires_at = datetime.fromisoformat(
            refresh_expires_at_raw.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise RuntimeError("stored desktop session expiry is invalid") from exc
    if access_expires_at.tzinfo is None or refresh_expires_at.tzinfo is None:
        raise RuntimeError("stored desktop session expiry must include a timezone")
    return DesktopSession(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
    )
