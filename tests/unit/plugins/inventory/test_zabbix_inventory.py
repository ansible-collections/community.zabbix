# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import io
import json
import pytest
from unittest.mock import patch

from ansible import constants as C
from ansible.errors import AnsibleParserError
from ansible.inventory.data import InventoryData
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.loader import fragment_loader
from ansible.utils.plugin_docs import get_docstring

from ansible_collections.community.zabbix.plugins.inventory import zabbix_inventory
from ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory import (
    InventoryModule,
)

PLUGIN_NAME = "community.zabbix.zabbix_inventory"
REQUEST_PATH = "ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory.Request"
ZABBIX_ENV_VARS = (
    "ZABBIX_SERVER",
    "ZABBIX_USERNAME",
    "ZABBIX_PASSWORD",
    "ZABBIX_AUTH_TOKEN",
    "ZABBIX_API_KEY",
    "ZABBIX_VALIDATE_CERTS",
)


@pytest.fixture(autouse=True)
def clean_zabbix_env(monkeypatch):
    """Make sure environment variables of the caller do not leak into option resolution."""
    for var in ZABBIX_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def inventory_plugin():
    """Return a plugin instance whose options are backed by its real DOCUMENTATION schema.

    The plugin loader normally registers the option definitions (including the
    ``constructed`` and ``inventory_cache`` doc fragments) with the config manager.
    Do the same here so ``set_options``/``get_option`` resolve aliases, env vars and
    defaults exactly like they do at runtime.
    """
    doc = get_docstring(
        zabbix_inventory.__file__,
        fragment_loader,
        collection_name="community.zabbix",
        plugin_type="inventory",
    )[0]
    C.config.initialize_plugin_configuration_definitions("inventory", PLUGIN_NAME, doc["options"])

    plugin = InventoryModule()
    plugin._load_name = PLUGIN_NAME
    plugin._redirected_names = [PLUGIN_NAME]
    return plugin


def _write_config(tmp_path, config):
    path = tmp_path / "zabbix_inventory.yml"
    path.write_text(json.dumps(dict(plugin=PLUGIN_NAME, **config)))
    return str(path)


def _mock_response(data):
    """Return a file-like HTTP response body containing serialized JSON data."""
    return io.BytesIO(json.dumps(data).encode("utf-8"))


def _fake_zabbix(version, recorded_requests, hosts=None):
    """Build a fake ``Request().post`` implementation emulating a Zabbix server."""
    def fake_post(url, data=None, **kwargs):
        payload = json.loads(data)
        recorded_requests.append({"url": url, "payload": payload})
        method = payload["method"]
        if method == "apiinfo.version":
            result = version
        elif method == "user.login":
            result = "session-auth-token"
        elif method == "host.get":
            result = hosts or []
        else:
            result = {}
        return _mock_response({"jsonrpc": "2.0", "result": result, "id": "1"})
    return fake_post


def _run_parse(inventory_plugin, tmp_path, config, version, hosts=None):
    """Run the full ``parse()`` path against a fake Zabbix server."""
    path = _write_config(tmp_path, config)
    recorded_requests = []

    with patch(REQUEST_PATH) as mock_req_class, patch.object(zabbix_inventory.atexit, "register") as mock_atexit:
        mock_req_class.return_value.post.side_effect = _fake_zabbix(version, recorded_requests, hosts)
        inventory_plugin.parse(InventoryData(), DataLoader(), path, cache=False)

    return recorded_requests, mock_req_class, mock_atexit


def _sent_headers(mock_req_class):
    return [c.kwargs["headers"] for c in mock_req_class.call_args_list]


def test_auth_with_login_token_alias_zabbix8(inventory_plugin, tmp_path):
    """``login_token`` is resolved to ``auth_token`` and used as a Bearer token on Zabbix 8.0.

    ``user.login`` must never be called and no logout handler may be registered.
    """
    config = {
        "server_url": "https://zabbix8.example.com",
        "login_token": "zbx-secret-token-12345",
    }
    hosts = [{"host": "node1.example.com", "status": "0"}]

    recorded, mock_req_class, mock_atexit = _run_parse(inventory_plugin, tmp_path, config, "8.0.0", hosts)

    assert inventory_plugin.get_option("auth_token") == "zbx-secret-token-12345"
    assert inventory_plugin.auth == "zbx-secret-token-12345"
    assert inventory_plugin.zabbix_version == "8.0.0"

    methods_called = [r["payload"]["method"] for r in recorded]
    assert methods_called == ["apiinfo.version", "host.get"]
    assert "user.login" not in methods_called
    mock_atexit.assert_not_called()

    headers = _sent_headers(mock_req_class)
    # apiinfo.version is an unauthenticated call
    assert "Authorization" not in headers[0]
    assert headers[1]["Authorization"] == "Bearer zbx-secret-token-12345"
    assert "auth" not in recorded[1]["payload"]

    assert "node1.example.com" in inventory_plugin.inventory.hosts


@pytest.mark.parametrize("env_var", ["ZABBIX_AUTH_TOKEN", "ZABBIX_API_KEY"])
def test_auth_token_from_environment(inventory_plugin, tmp_path, monkeypatch, env_var):
    """``auth_token`` can be supplied through the documented environment variables."""
    monkeypatch.setenv(env_var, "zbx-env-token")
    config = {"server_url": "https://zabbix8.example.com"}

    recorded, mock_req_class, mock_atexit = _run_parse(inventory_plugin, tmp_path, config, "8.0.0")

    assert inventory_plugin.get_option("auth_token") == "zbx-env-token"
    assert "user.login" not in [r["payload"]["method"] for r in recorded]
    assert _sent_headers(mock_req_class)[1]["Authorization"] == "Bearer zbx-env-token"
    mock_atexit.assert_not_called()


def test_auth_with_user_password_legacy(inventory_plugin, tmp_path):
    """Username/password login keeps working through the real config parsing path.

    With no ``auth_token``/``login_token`` configured, option lookups must not fail and
    the plugin falls back to ``user.login`` on legacy Zabbix (6.x), sending the
    session token in the JSON-RPC ``auth`` field.
    """
    config = {
        "server_url": "https://zabbix6.example.com",
        "login_user": "Admin",
        "login_password": "zabbix_password",
    }

    recorded, mock_req_class, mock_atexit = _run_parse(inventory_plugin, tmp_path, config, "6.0.12")

    assert inventory_plugin.get_option("auth_token") is None
    assert inventory_plugin.zabbix_version == "6.0.12"
    assert inventory_plugin.auth == "session-auth-token"

    methods_called = [r["payload"]["method"] for r in recorded]
    assert methods_called == ["apiinfo.version", "user.login", "host.get"]

    login_params = recorded[1]["payload"]["params"]
    assert login_params == {"username": "Admin", "password": "zabbix_password"}

    assert recorded[2]["payload"]["auth"] == "session-auth-token"
    assert all("Authorization" not in h for h in _sent_headers(mock_req_class))

    mock_atexit.assert_called_once_with(inventory_plugin.logout_zabbix)


def test_api_call_error_handling(inventory_plugin):
    """JSON-RPC errors returned by Zabbix are reported instead of raising ``KeyError: 'result'``."""
    inventory_plugin.set_options(direct={
        "server_url": "https://zabbix.example.com",
        "auth_token": "token",
    })

    error_response = {
        "jsonrpc": "2.0",
        "error": {
            "code": -32602,
            "message": "Invalid params.",
            "data": "The \"auth\" parameter must not be used if the authorization HTTP header is present."
        },
        "id": "1"
    }

    with patch(REQUEST_PATH) as mock_req_class:
        mock_req_class.return_value.post.return_value = _mock_response(error_response)

        with pytest.raises(AnsibleParserError) as excinfo:
            inventory_plugin._api_call("host.get", {})
    assert "Zabbix API error (-32602): Invalid params." in str(excinfo.value)
