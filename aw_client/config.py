import logging
from typing import Optional, Union

from aw_core.config import load_config_toml

from .desktop_session import DesktopSessionStore

logger = logging.getLogger(__name__)

default_config = """
[server]
protocol = "http"
hostname = "127.0.0.1"
port = "5600"

[client]
commit_interval = 10

[server-testing]
protocol = "http"
hostname = "127.0.0.1"
port = "5666"

[client-testing]
commit_interval = 5
""".strip()


def load_config():
    return load_config_toml("aw-client", default_config)


def load_server_api_key(host: str, port: Union[int, str]) -> Optional[str]:
    try:
        session = DesktopSessionStore(host, port).load()
    except (TypeError, ValueError):
        return None
    return session.access_token if session is not None else None
