# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import io
import json
import pytest
from unittest.mock import MagicMock, patch

from ansible.inventory.data import InventoryData
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
from ansible.errors import AnsibleParserError

from ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory import (
    InventoryModule,
)


@pytest.fixture
def inventory_plugin():
    plugin = InventoryModule()
    plugin.inventory = InventoryData()
    plugin.loader = DataLoader()
    plugin.templar = Templar(loader=plugin.loader)
    return plugin


def _mock_response(data):
    """Create a mock HTTP response returning serialized JSON data."""
    mock = MagicMock()
    mock.read.return_value = json.dumps(data).encode("utf-8")
    mock.readinto = None
    stream = io.BytesIO(json.dumps(data).encode("utf-8"))
    stream.info = MagicMock(return_value={})
    stream.getcode = MagicMock(return_value=200)
    return stream


def test_auth_with_login_token_zabbix8(inventory_plugin):
    """Test authentication with login_token (alias of auth_token) targeting Zabbix 8.0.

    Verifies user.login is never called and Bearer token is sent in HTTP Authorization header.
    """
    options = {
        "server_url": "https://zabbix8.example.com",
        "login_token": "zbx-secret-token-12345",
        "auth_token": "zbx-secret-token-12345",
        "login_user": None,
        "login_password": None,
        "proxy": "",
        "validate_certs": True,
        "timeout": 10,
        "cache": False,
        "strict": False,
        "compose": {},
        "groups": {},
        "keyed_groups": [],
        "host_zapi_query": {},
        "add_zabbix_groups": False,
    }
    inventory_plugin.get_option = lambda opt: options.get(opt, None)

    recorded_requests = []

    def fake_post(url, data=None, **kwargs):
        payload = json.loads(data)
        recorded_requests.append({
            "url": url,
            "payload": payload,
        })
        method = payload.get("method")
        if method == "apiinfo.version":
            return _mock_response({"jsonrpc": "2.0", "result": "8.0.0", "id": "1"})
        elif method == "host.get":
            return _mock_response({
                "jsonrpc": "2.0",
                "result": [
                    {"host": "node1.example.com", "status": "0"}
                ],
                "id": "1"
            })
        elif method == "user.login":
            pytest.fail("user.login should never be called when token is provided!")
        return _mock_response({"jsonrpc": "2.0", "result": {}, "id": "1"})

    with patch("ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory.Request") as mock_req_class:
        mock_req_instance = MagicMock()
        mock_req_instance.post.side_effect = fake_post
        mock_req_class.return_value = mock_req_instance

        inventory_plugin.get_version()
        assert inventory_plugin.zabbix_version == "8.0.0"

        inventory_plugin.login_zabbix()
        assert inventory_plugin.auth == "zbx-secret-token-12345"

        # Subsequent requests must include Authorization Bearer header
        inventory_plugin.api_request("host.get", {})
        assert mock_req_class.called
        headers = mock_req_class.call_args[1].get("headers", {})
        assert headers.get("Authorization") == "Bearer zbx-secret-token-12345"

    methods_called = [r["payload"]["method"] for r in recorded_requests]
    assert "user.login" not in methods_called
    assert "apiinfo.version" in methods_called


def test_auth_with_user_password_legacy(inventory_plugin):
    """Test fallback and backward compatibility for username/password login on legacy Zabbix (6.x)."""
    options = {
        "server_url": "https://zabbix6.example.com",
        "auth_token": None,
        "login_token": None,
        "login_user": "Admin",
        "login_password": "zabbix_password",
        "proxy": "",
        "validate_certs": True,
        "timeout": 10,
        "cache": False,
        "strict": False,
        "compose": {},
        "groups": {},
        "keyed_groups": [],
        "host_zapi_query": {},
        "add_zabbix_groups": False,
    }
    inventory_plugin.get_option = lambda opt: options.get(opt, None)

    recorded_requests = []

    def fake_post(url, data=None, **kwargs):
        payload = json.loads(data)
        recorded_requests.append({
            "url": url,
            "payload": payload,
        })
        method = payload.get("method")
        if method == "apiinfo.version":
            return _mock_response({"jsonrpc": "2.0", "result": "6.0.12", "id": "1"})
        elif method == "user.login":
            assert payload["params"]["username"] == "Admin"
            assert payload["params"]["password"] == "zabbix_password"
            return _mock_response({"jsonrpc": "2.0", "result": "session-auth-token-60", "id": "1"})
        elif method == "host.get":
            assert payload.get("auth") == "session-auth-token-60"
            return _mock_response({"jsonrpc": "2.0", "result": [], "id": "1"})
        return _mock_response({"jsonrpc": "2.0", "result": {}, "id": "1"})

    with patch("ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory.Request") as mock_req_class:
        mock_req_instance = MagicMock()
        mock_req_instance.post.side_effect = fake_post
        mock_req_class.return_value = mock_req_instance

        inventory_plugin.get_version()
        assert inventory_plugin.zabbix_version == "6.0.12"

        inventory_plugin.login_zabbix()
        assert inventory_plugin.auth == "session-auth-token-60"

    methods_called = [r["payload"]["method"] for r in recorded_requests]
    assert "user.login" in methods_called


def test_group_name_sanitization(inventory_plugin, recwarn):
    """Test that group names containing colons and slashes are properly sanitized without warnings."""
    test_cases = [
        ("k8s:cluster/component", "k8s_cluster_component"),
        ("Kubernetes/Core:APIServer", "Kubernetes_Core_APIServer"),
        ("simple_group", "simple_group"),
        ("group/with/multiple:colons:and/slashes", "group_with_multiple_colons_and_slashes"),
    ]

    for raw_name, expected in test_cases:
        sanitized = inventory_plugin._sanitize_group_name(raw_name)
        assert sanitized == expected

        # Adding sanitized group to inventory should not produce Ansible group warnings
        inventory_plugin.inventory.add_group(sanitized)

    # Verify no warning about invalid group name was raised
    group_warnings = [
        w for w in recwarn
        if "Invalid characters were found in group names" in str(w.message)
    ]
    assert len(group_warnings) == 0


def test_api_call_error_handling(inventory_plugin):
    """Test that JSON-RPC errors returned by Zabbix are handled gracefully."""
    options = {
        "server_url": "https://zabbix.example.com",
        "auth_token": "token",
        "proxy": "",
        "validate_certs": True,
        "timeout": 10,
    }
    inventory_plugin.get_option = lambda opt: options.get(opt, None)

    error_response = {
        "jsonrpc": "2.0",
        "error": {
            "code": -32602,
            "message": "Invalid params.",
            "data": "The \"auth\" parameter must not be used if the authorization HTTP header is present."
        },
        "id": "1"
    }

    with patch("ansible_collections.community.zabbix.plugins.inventory.zabbix_inventory.Request") as mock_req_class:
        mock_req_instance = MagicMock()
        mock_req_instance.post.return_value = _mock_response(error_response)
        mock_req_class.return_value = mock_req_instance

        with pytest.raises(AnsibleParserError) as excinfo:
            inventory_plugin._api_call("host.get", {})
        assert "Zabbix API error (-32602): Invalid params." in str(excinfo.value)
