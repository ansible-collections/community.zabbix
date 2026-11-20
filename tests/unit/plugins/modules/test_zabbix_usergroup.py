# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from unittest.mock import MagicMock

import pytest

from ansible.module_utils import basic
from ansible_collections.community.zabbix.plugins.module_utils import base
from ansible_collections.community.zabbix.plugins.modules import zabbix_usergroup


class ModuleResult(BaseException):
    def __init__(self, **kwargs):
        self.result = kwargs


@pytest.fixture
def api(monkeypatch):
    api = MagicMock()
    api.api_version.return_value = "8.0.0"
    api.usergroup.get.return_value = []
    api.usergroup.create.return_value = {"usrgrpids": ["42"]}
    api.proxy.get.side_effect = lambda params: [
        {"proxyid": {"Branch": "10", "Office": "11"}[params["filter"]["name"][0]]}
    ]
    api.proxygroup.get.return_value = [{"proxy_groupid": "20"}]
    api.mfa.get.return_value = [{"mfaid": "30", "name": "Corporate TOTP"}]
    monkeypatch.setattr(base, "ZabbixApiRequest", lambda module: api)
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", lambda self, **kwargs: exit_module(**kwargs))
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", lambda self, **kwargs: exit_module(failed=True, **kwargs))
    return api


def exit_module(**kwargs):
    raise ModuleResult(**kwargs)


def run_module(monkeypatch, **kwargs):
    args = {"name": "ACME"}
    args.update(kwargs)
    monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode("utf-8"))
    with pytest.raises(ModuleResult) as result:
        zabbix_usergroup.main()
    return result.value.result


def existing_group(**kwargs):
    group = dict(
        usrgrpid="42", name="ACME", gui_access="0", debug_mode="0", users_status="0",
        hostgroup_rights=[], templategroup_rights=[], tag_filters=[], apm_filters=[],
        proxy_mode="0", proxies=[{"proxyid": "11"}, {"proxyid": "10"}],
        proxy_group_mode="1", proxy_groups=[{"proxy_groupid": "20"}],
        mfa_status="1", mfaid="0",
    )
    group.update(kwargs)
    return [group]


def test_create_proxy_permissions(api, monkeypatch):
    result = run_module(
        monkeypatch, proxy_mode="deny_list", proxies=["Branch"],
        proxy_group_mode="allow_list", proxy_groups=["Production"],
    )
    assert result["changed"]
    params = api.usergroup.create.call_args[0][0]
    assert params["proxy_mode"] == 0
    assert params["proxy_group_mode"] == 1
    assert params["proxies"] == [{"proxyid": "10"}]
    assert params["proxy_groups"] == [{"proxy_groupid": "20"}]
    api.proxy.get.assert_called_once_with({"output": ["proxyid"], "filter": {"name": ["Branch"]}})
    api.proxygroup.get.assert_called_once_with({"output": ["proxy_groupid"], "filter": {"name": ["Production"]}})


def test_create_omits_unspecified_permissions(api, monkeypatch):
    assert run_module(monkeypatch)["changed"]
    params = api.usergroup.create.call_args[0][0]
    for field in ("proxy_mode", "proxies", "proxy_group_mode", "proxy_groups", "apm_filters", "mfa_status", "mfaid"):
        assert field not in params
    api.proxy.get.assert_not_called()
    api.proxygroup.get.assert_not_called()


def test_permissions_are_idempotent_and_unordered(api, monkeypatch):
    api.usergroup.get.return_value = existing_group()
    result = run_module(
        monkeypatch, proxy_mode="deny_list", proxies=["Branch", "Office"],
        proxy_group_mode="allow_list", proxy_groups=["Production"],
    )
    assert not result["changed"]
    api.usergroup.update.assert_not_called()
    params = api.usergroup.get.call_args[0][0]
    assert params["selectProxies"] == ["proxyid"]
    assert params["selectProxyGroups"] == ["proxy_groupid"]


def test_omitted_permissions_are_preserved(api, monkeypatch):
    api.usergroup.get.return_value = existing_group()
    result = run_module(monkeypatch, debug_mode="enabled")
    assert result["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "debug_mode": "1"})
    for call in api.usergroup.get.call_args_list:
        assert "selectProxies" not in call[0][0]
        assert "selectProxyGroups" not in call[0][0]


def test_update_modes_and_lists(api, monkeypatch):
    api.usergroup.get.return_value = existing_group()
    result = run_module(
        monkeypatch, proxy_mode="allow_list", proxies=["Branch"],
        proxy_group_mode="deny_list", proxy_groups=[],
    )
    assert result["changed"]
    api.usergroup.update.assert_called_once_with({
        "usrgrpid": "42", "proxy_mode": "1", "proxies": [{"proxyid": "10"}],
        "proxy_group_mode": "0", "proxy_groups": [],
    })


def test_empty_lists_clear_permissions(api, monkeypatch):
    api.usergroup.get.return_value = existing_group()
    assert run_module(monkeypatch, proxies=[], proxy_groups=[])["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "proxies": [], "proxy_groups": []})
    api.proxy.get.assert_not_called()
    api.proxygroup.get.assert_not_called()


def test_empty_lists_are_idempotent(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(proxies=[], proxy_groups=[])
    assert not run_module(monkeypatch, proxies=[], proxy_groups=[])["changed"]
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("existing", [False, True])
def test_check_mode_does_not_write(api, monkeypatch, existing):
    if existing:
        api.usergroup.get.return_value = existing_group()
    result = run_module(monkeypatch, proxy_mode="allow_list", proxies=["Branch"], _ansible_check_mode=True)
    assert result["changed"]
    api.usergroup.create.assert_not_called()
    api.usergroup.update.assert_not_called()
    api.proxy.get.assert_called_once()


def test_check_mode_unchanged(api, monkeypatch):
    api.usergroup.get.return_value = existing_group()
    result = run_module(monkeypatch, proxies=["Branch", "Office"], _ansible_check_mode=True)
    assert not result["changed"]
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("option,label,resource", [
    ("proxies", "Proxy", "proxy"), ("proxy_groups", "Proxy group", "proxygroup"),
])
@pytest.mark.parametrize("check_mode", [False, True])
def test_missing_proxy_is_rejected(api, monkeypatch, option, label, resource, check_mode):
    getattr(api, resource).get.side_effect = None
    getattr(api, resource).get.return_value = []
    result = run_module(monkeypatch, **{option: ["Missing"], "_ansible_check_mode": check_mode})
    assert result["failed"]
    assert result["msg"] == "%s not found: Missing" % label
    api.usergroup.create.assert_not_called()
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("option,resource", [("proxies", "proxy"), ("proxy_groups", "proxygroup")])
def test_lookup_error_is_reported(api, monkeypatch, option, resource):
    getattr(api, resource).get.side_effect = Exception("API unavailable")
    result = run_module(monkeypatch, **{option: ["Branch"]})
    assert result["failed"]
    assert "API unavailable" in result["msg"]
    api.usergroup.create.assert_not_called()


def test_duplicate_names_are_normalized(api, monkeypatch):
    assert run_module(monkeypatch, proxies=["Branch", "Branch"])["changed"]
    assert api.usergroup.create.call_args[0][0]["proxies"] == [{"proxyid": "10"}]
    api.proxy.get.assert_called_once()


@pytest.mark.parametrize("version", ["6.0.0", "7.0.0", "7.4.0"])
@pytest.mark.parametrize("option,value", [
    ("proxy_mode", "deny_list"), ("proxy_group_mode", "allow_list"),
    ("proxies", []), ("proxy_groups", []),
    ("apm_filters", []), ("apm_filters", [{"key": "service.name"}]),
    ("mfa_status", "disabled"), ("mfa_method", ""),
])
def test_old_versions_reject_proxy_options(api, monkeypatch, version, option, value):
    api.api_version.return_value = version
    result = run_module(monkeypatch, **{option: value})
    assert result["failed"]
    assert result["msg"] == "%s is supported from Zabbix 8.0" % option
    api.usergroup.get.assert_not_called()
    api.usergroup.create.assert_not_called()


@pytest.mark.parametrize("version", ["6.0.0", "7.0.0", "7.4.0"])
def test_old_versions_do_not_send_proxy_fields(api, monkeypatch, version):
    api.api_version.return_value = version
    api.usergroup.get.return_value = existing_group(rights=[])
    assert not run_module(monkeypatch)["changed"]
    for call in api.usergroup.get.call_args_list:
        assert "selectProxies" not in call[0][0]
        assert "selectProxyGroups" not in call[0][0]
        assert "selectApmFilters" not in call[0][0]
    api.proxy.get.assert_not_called()
    api.proxygroup.get.assert_not_called()


@pytest.mark.parametrize("status,numeric", [("disabled", 0), ("enabled", 1)])
def test_create_mfa_status(api, monkeypatch, status, numeric):
    assert run_module(monkeypatch, mfa_status=status)["changed"]
    params = api.usergroup.create.call_args[0][0]
    assert params["mfa_status"] == numeric
    if status == "disabled":
        assert params["mfaid"] == "0"
    else:
        assert "mfaid" not in params
    api.mfa.get.assert_not_called()


def test_create_mfa_method(api, monkeypatch):
    assert run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP")["changed"]
    params = api.usergroup.create.call_args[0][0]
    assert params["mfa_status"] == 1
    assert params["mfaid"] == "30"
    api.mfa.get.assert_called_once_with({"output": ["mfaid", "name"], "search": {"name": "Corporate TOTP"}})


@pytest.mark.parametrize("check_mode", [False, True])
def test_mfa_is_idempotent(api, monkeypatch, check_mode):
    api.usergroup.get.return_value = existing_group(mfa_status="1", mfaid="30")
    result = run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP", _ansible_check_mode=check_mode)
    assert not result["changed"]
    api.usergroup.update.assert_not_called()


def test_omitted_mfa_settings_are_preserved(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(mfa_status="0", mfaid="0")
    assert run_module(monkeypatch, debug_mode="enabled")["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "debug_mode": "1"})
    api.mfa.get.assert_not_called()


def test_status_only_preserves_mfa_method(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(mfaid="30")
    assert not run_module(monkeypatch, mfa_status="enabled")["changed"]
    api.usergroup.update.assert_not_called()
    api.mfa.get.assert_not_called()


def test_change_mfa_method(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(mfaid="31")
    assert run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP")["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "mfaid": "30"})


def test_reset_mfa_method_to_default(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(mfaid="30")
    assert run_module(monkeypatch, mfa_status="enabled", mfa_method="")["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "mfaid": "0"})
    api.mfa.get.assert_not_called()


def test_disable_mfa_resets_method(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(mfaid="30")
    assert run_module(monkeypatch, mfa_status="disabled")["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "mfa_status": "0", "mfaid": "0"})


@pytest.mark.parametrize("existing", [False, True])
def test_mfa_check_mode_does_not_write(api, monkeypatch, existing):
    if existing:
        api.usergroup.get.return_value = existing_group()
    assert run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP", _ansible_check_mode=True)["changed"]
    api.usergroup.create.assert_not_called()
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("status", [None, "disabled"])
@pytest.mark.parametrize("method", ["", "Corporate TOTP"])
def test_mfa_method_requires_enabled_status(api, monkeypatch, status, method):
    params = {"mfa_method": method}
    if status is not None:
        params["mfa_status"] = status
    result = run_module(monkeypatch, **params)
    assert result["failed"]
    assert result["msg"] == "mfa_method requires mfa_status=enabled"
    api.usergroup.get.assert_not_called()
    api.usergroup.create.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_mfa_method_lookup_requires_exact_name(api, monkeypatch, check_mode):
    api.mfa.get.return_value = [{"mfaid": "30", "name": "Corporate TOTP other"}]
    result = run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP", _ansible_check_mode=check_mode)
    assert result["failed"]
    assert result["msg"] == "MFA method not found: Corporate TOTP"
    api.usergroup.create.assert_not_called()


def test_mfa_method_lookup_error(api, monkeypatch):
    api.mfa.get.side_effect = Exception("API unavailable")
    result = run_module(monkeypatch, mfa_status="enabled", mfa_method="Corporate TOTP")
    assert result["failed"]
    assert "Failed to get MFA method 'Corporate TOTP': API unavailable" == result["msg"]
    api.usergroup.create.assert_not_called()


@pytest.mark.parametrize("status", ["disabled", "enabled"])
def test_mfa_default_settings_are_idempotent(api, monkeypatch, status):
    api.usergroup.get.return_value = existing_group(mfa_status="1" if status == "enabled" else "0", mfaid="0")
    params = {"mfa_status": status}
    if status == "enabled":
        params["mfa_method"] = ""
    assert not run_module(monkeypatch, **params)["changed"]
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("signal_type,numeric", [("all", -1), ("traces", 0), ("metrics", 1), ("logs", 2)])
def test_create_apm_signal_types(api, monkeypatch, signal_type, numeric):
    result = run_module(monkeypatch, apm_filters=[{"key": "service.name", "value": "checkout", "signal_type": signal_type}])
    assert result["changed"]
    assert api.usergroup.create.call_args[0][0]["apm_filters"] == [
        {"key": "service.name", "value": "checkout", "signal_type": numeric},
    ]


def test_apm_filter_defaults(api, monkeypatch):
    assert run_module(monkeypatch, apm_filters=[{"key": "service.name"}])["changed"]
    assert api.usergroup.create.call_args[0][0]["apm_filters"] == [
        {"key": "service.name", "value": "", "signal_type": -1},
    ]


@pytest.mark.parametrize("check_mode", [False, True])
def test_apm_filters_are_idempotent_and_unordered(api, monkeypatch, check_mode):
    api.usergroup.get.return_value = existing_group(apm_filters=[
        {"key": "service.name", "value": "", "signal_type": "-1"},
        {"key": "service.namespace", "value": "production", "signal_type": "0"},
    ])
    result = run_module(monkeypatch, apm_filters=[
        {"key": "service.namespace", "value": "production", "signal_type": "traces"},
        {"key": "service.name"},
    ], _ansible_check_mode=check_mode)
    assert not result["changed"]
    api.usergroup.update.assert_not_called()
    assert api.usergroup.get.call_args[0][0]["selectApmFilters"] == ["key", "value", "signal_type"]


def test_omitted_apm_filters_are_preserved(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(apm_filters=[
        {"key": "service.name", "value": "checkout", "signal_type": "0"},
    ])
    assert run_module(monkeypatch, debug_mode="enabled")["changed"]
    api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "debug_mode": "1"})
    for call in api.usergroup.get.call_args_list:
        assert "selectApmFilters" not in call[0][0]


def test_apm_filters_are_replaced(api, monkeypatch):
    api.usergroup.get.return_value = existing_group(apm_filters=[
        {"key": "service.name", "value": "checkout", "signal_type": "0"},
    ])
    assert run_module(monkeypatch, apm_filters=[{"key": "service.namespace", "signal_type": "logs"}])["changed"]
    api.usergroup.update.assert_called_once_with({
        "usrgrpid": "42", "apm_filters": [{"key": "service.namespace", "value": "", "signal_type": "2"}],
    })


@pytest.mark.parametrize("existing", [False, True])
def test_apm_check_mode_does_not_write(api, monkeypatch, existing):
    if existing:
        api.usergroup.get.return_value = existing_group()
    assert run_module(monkeypatch, apm_filters=[{"key": "service.name"}], _ansible_check_mode=True)["changed"]
    api.usergroup.create.assert_not_called()
    api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("filters,changed", [([], False), ([{"key": "service.name", "value": "", "signal_type": "-1"}], True)])
def test_clear_apm_filters(api, monkeypatch, filters, changed):
    api.usergroup.get.return_value = existing_group(apm_filters=filters)
    assert run_module(monkeypatch, apm_filters=[])["changed"] == changed
    if changed:
        api.usergroup.update.assert_called_once_with({"usrgrpid": "42", "apm_filters": []})
    else:
        api.usergroup.update.assert_not_called()


@pytest.mark.parametrize("filters,message", [
    ([{"value": "checkout"}], "key"),
    ([{"key": ""}], "apm_filters key must not be empty"),
    ([{"key": "service.name", "signal_type": "invalid"}], "signal_type"),
    ([{"key": "service.name"}, {"key": "service.name", "value": "", "signal_type": "all"}], "duplicate"),
])
@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_apm_filters_are_rejected(api, monkeypatch, filters, message, check_mode):
    result = run_module(monkeypatch, apm_filters=filters, _ansible_check_mode=check_mode)
    assert result["failed"]
    assert message in result["msg"]
    api.usergroup.create.assert_not_called()
    api.usergroup.update.assert_not_called()
