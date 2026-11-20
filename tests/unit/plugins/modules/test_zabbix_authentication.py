# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import json
from unittest.mock import MagicMock

import pytest
from ansible.module_utils import basic
from ansible_collections.community.zabbix.plugins.module_utils import base
from ansible_collections.community.zabbix.plugins.modules import zabbix_authentication, zabbix_mfa, zabbix_user_directory


class ModuleResult(BaseException):
    def __init__(self, **kwargs):
        self.result = kwargs


def finish(**kwargs):
    raise ModuleResult(**kwargs)


@pytest.fixture
def api(monkeypatch):
    api = MagicMock()
    api.api_version.return_value = "8.0.0"
    api.authentication.get.return_value = dict(
        authentication_type="0", http_auth_enabled="0", http_login_form="0", http_strip_domains="",
        http_case_sensitive="1", ldap_auth_enabled="0", ldap_userdirectoryid="0", ldap_case_sensitive="1",
        saml_auth_enabled="0", saml_case_sensitive="1", ldap_jit_status="0", saml_jit_status="0",
        jit_provision_interval="2h", disabled_usrgrpid="0", passwd_min_length="8", passwd_check_rules="8",
        mfa_status="0", mfaid="0",
    )
    api.userdirectory.get.return_value = []
    api.mfa.get.return_value = []
    api.usergroup.get.return_value = []
    monkeypatch.setattr(base, "ZabbixApiRequest", lambda module: api)
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", lambda self, **kwargs: finish(**kwargs))
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", lambda self, **kwargs: finish(failed=True, **kwargs))
    return api


def run(monkeypatch, module=zabbix_authentication, **kwargs):
    monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": kwargs}).encode())
    with pytest.raises(ModuleResult) as result:
        module.main()
    return result.value.result


def test_no_options_preserve_authentication(api, monkeypatch):
    assert not run(monkeypatch)["changed"]
    api.authentication.update.assert_not_called()


@pytest.mark.parametrize("field", [
    "http_auth_enabled", "http_case_sensitive", "ldap_auth_enabled", "ldap_case_sensitive",
    "saml_auth_enabled", "saml_case_sensitive", "ldap_jit_status", "saml_jit_status", "mfa_status",
])
@pytest.mark.parametrize("value", [False, True])
def test_authentication_boolean_updates(api, monkeypatch, field, value):
    current = api.authentication.get.return_value
    current.update(ldap_userdirectoryid="10", disabled_usrgrpid="20", mfaid="30")
    current[field] = str(int(not value))
    assert run(monkeypatch, **{field: value})["changed"]
    api.authentication.update.assert_called_once_with({field: str(int(value))})


@pytest.mark.parametrize("field,value,numeric", [
    ("authentication_type", "internal", "0"), ("authentication_type", "ldap", "1"),
    ("http_login_form", "zabbix_login_form", "0"), ("http_login_form", "http_login_form", "1"),
])
def test_authentication_enums(api, monkeypatch, field, value, numeric):
    api.authentication.get.return_value.update(ldap_auth_enabled="1", ldap_userdirectoryid="10")
    api.authentication.get.return_value[field] = str(1 - int(numeric))
    assert run(monkeypatch, **{field: value})["changed"]
    api.authentication.update.assert_called_once_with({field: numeric})


@pytest.mark.parametrize("domains,expected", [([], ""), (["corp", "example"], "corp,example")])
def test_http_domains_can_be_set_and_cleared(api, monkeypatch, domains, expected):
    api.authentication.get.return_value["http_strip_domains"] = "old"
    assert run(monkeypatch, http_strip_domains=domains)["changed"]
    api.authentication.update.assert_called_once_with({"http_strip_domains": expected})


def test_mfa_name_is_resolved_exactly(api, monkeypatch):
    api.mfa.get.return_value = [{"name": "TOTP other", "mfaid": "31"}, {"name": "TOTP", "mfaid": "30"}]
    assert run(monkeypatch, mfa_status=True, mfa_method="TOTP")["changed"]
    api.authentication.update.assert_called_once_with({"mfa_status": "1", "mfaid": "30"})


def test_missing_mfa_is_rejected(api, monkeypatch):
    api.mfa.get.return_value = [{"name": "TOTP other", "mfaid": "31"}]
    assert run(monkeypatch, mfa_status=True, mfa_method="TOTP")["failed"]
    api.authentication.update.assert_not_called()


@pytest.mark.parametrize("enabled", [False, True])
def test_clearing_default_mfa_requires_disabled_mfa(api, monkeypatch, enabled):
    api.authentication.get.return_value.update(mfa_status="1" if enabled else "0", mfaid="30")
    result = run(monkeypatch, mfa_method="")
    if enabled:
        assert result["failed"]
        api.authentication.update.assert_not_called()
    else:
        assert result["changed"]
        api.authentication.update.assert_called_once_with({"mfaid": "0"})


def test_mfa_can_use_existing_default(api, monkeypatch):
    api.authentication.get.return_value["mfaid"] = "30"
    assert run(monkeypatch, mfa_status=True)["changed"]
    api.authentication.update.assert_called_once_with({"mfa_status": "1"})


def test_mfa_cannot_be_enabled_without_default(api, monkeypatch):
    assert run(monkeypatch, mfa_status=True)["failed"]
    api.authentication.update.assert_not_called()


@pytest.mark.parametrize("kwargs", [{"mfa_status": False}, {"mfa_method": ""}])
def test_mfa_options_are_version_gated(api, monkeypatch, kwargs):
    api.api_version.return_value = "7.0.0"
    assert run(monkeypatch, **kwargs)["failed"]
    api.authentication.get.assert_not_called()


def test_ldap_directory_lookup_is_exact_and_ldap_only(api, monkeypatch):
    api.userdirectory.get.return_value = [
        {"name": "LDAP other", "idp_type": "1", "userdirectoryid": "11"},
        {"name": "LDAP", "idp_type": "1", "userdirectoryid": "10"},
    ]
    assert run(monkeypatch, ldap_auth_enabled=True, ldap_userdirectory="LDAP")["changed"]
    api.authentication.update.assert_called_once_with({"ldap_auth_enabled": "1", "ldap_userdirectoryid": "10"})


@pytest.mark.parametrize("provider", [
    [], [{"name": "LDAP other", "idp_type": "1", "userdirectoryid": "10"}],
    [{"name": "LDAP", "idp_type": "2", "userdirectoryid": "10"}],
])
def test_wrong_ldap_directory_is_rejected(api, monkeypatch, provider):
    api.userdirectory.get.return_value = provider
    assert run(monkeypatch, ldap_userdirectory="LDAP")["failed"]
    api.authentication.update.assert_not_called()


def test_ldap_enable_reuses_existing_directory(api, monkeypatch):
    api.authentication.get.return_value["ldap_userdirectoryid"] = "10"
    assert run(monkeypatch, ldap_auth_enabled=True)["changed"]
    api.authentication.update.assert_called_once_with({"ldap_auth_enabled": "1"})


@pytest.mark.parametrize("kwargs", [{"ldap_auth_enabled": True}, {"authentication_type": "ldap"}])
def test_invalid_ldap_settings_are_rejected(api, monkeypatch, kwargs):
    assert run(monkeypatch, **kwargs)["failed"]
    api.authentication.update.assert_not_called()


def test_clear_ldap_reference_when_disabled(api, monkeypatch):
    api.authentication.get.return_value["ldap_userdirectoryid"] = "10"
    assert run(monkeypatch, ldap_userdirectory="")["changed"]
    api.authentication.update.assert_called_once_with({"ldap_userdirectoryid": "0"})


@pytest.mark.parametrize("status", ["0", "1"])
def test_provisioning_group_must_be_disabled(api, monkeypatch, status):
    api.usergroup.get.return_value = [{"usrgrpid": "20", "users_status": status}]
    result = run(monkeypatch, ldap_jit_status=True, disabled_usrgroup="Disabled")
    if status == "1":
        assert result["changed"]
    else:
        assert result["failed"]
        api.authentication.update.assert_not_called()


def test_existing_jit_group_is_preserved(api, monkeypatch):
    api.authentication.get.return_value["disabled_usrgrpid"] = "20"
    assert run(monkeypatch, saml_jit_status=True)["changed"]
    api.authentication.update.assert_called_once_with({"saml_jit_status": "1"})


def test_missing_provisioning_group_is_rejected(api, monkeypatch):
    assert run(monkeypatch, ldap_jit_status=True)["failed"]
    assert run(monkeypatch, disabled_usrgroup="Missing")["failed"]
    api.authentication.update.assert_not_called()


def test_clear_provisioning_group_after_disabling_jit(api, monkeypatch):
    api.authentication.get.return_value.update(ldap_jit_status="1", disabled_usrgrpid="20")
    assert run(monkeypatch, ldap_jit_status=False, disabled_usrgroup="")["changed"]
    api.authentication.update.assert_called_once_with({"ldap_jit_status": "0", "disabled_usrgrpid": "0"})


@pytest.mark.parametrize("rules,expected", [([], "0"), (["contain_digits", "contain_digits"], "2")])
def test_password_rules_are_a_bitmask(api, monkeypatch, rules, expected):
    assert run(monkeypatch, passwd_check_rules=rules)["changed"]
    api.authentication.update.assert_called_once_with({"passwd_check_rules": expected})


@pytest.mark.parametrize("length", [0, 71])
def test_invalid_password_length(api, monkeypatch, length):
    assert run(monkeypatch, passwd_min_length=length)["failed"]
    api.authentication.update.assert_not_called()


def test_http_feature_flag_is_checked(api, monkeypatch):
    del api.authentication.get.return_value["http_auth_enabled"]
    assert run(monkeypatch, http_auth_enabled=True)["failed"]
    api.authentication.update.assert_not_called()


def test_authentication_check_mode(api, monkeypatch):
    assert run(monkeypatch, http_auth_enabled=True, _ansible_check_mode=True)["changed"]
    api.authentication.update.assert_not_called()


def ldap_directory(**kwargs):
    directory = dict(name="LDAP", userdirectoryid="10", idp_type="1", host="ldap.example.com", port="389",
                     base_dn="dc=example,dc=com", search_attribute="uid", start_tls="1", description="old",
                     bind_dn="cn=search", search_filter="(uid=%{user})", provision_status="0", provision_media=[], provision_groups=[])
    directory.update(kwargs)
    return directory


def saml_directory(**kwargs):
    directory = dict(name="SAML", userdirectoryid="11", idp_type="2", idp_entityid="https://idp.example.com",
                     sp_entityid="zabbix", sso_url="https://idp.example.com/sso", username_attribute="uid",
                     provision_status="0", provision_groups=[], provision_media=[])
    directory.update(kwargs)
    return directory


def test_create_ldap_omits_optional_defaults(api, monkeypatch):
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", idp_type="ldap", host="ldap.example.com",
               port=389, base_dn="dc=example,dc=com", search_attribute="uid")["changed"]
    api.userdirectory.create.assert_called_once_with(dict(
        name="LDAP", idp_type=1, host="ldap.example.com", port=389, base_dn="dc=example,dc=com", search_attribute="uid",
    ))


@pytest.mark.parametrize("field,value", [("description", ""), ("bind_dn", ""), ("start_tls", 0)])
def test_ldap_partial_updates_preserve_empty_and_zero(api, monkeypatch, field, value):
    api.userdirectory.get.return_value = [ldap_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", **{field: value})["changed"]
    api.userdirectory.update.assert_called_once_with({"userdirectoryid": "10", field: value})


def test_ldap_update_selects_exact_name(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(name="LDAP other", userdirectoryid="12"), ldap_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", description="new")["changed"]
    api.userdirectory.update.assert_called_once_with({"userdirectoryid": "10", "description": "new"})


def test_omitted_directory_settings_are_preserved(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory()]
    assert not run(monkeypatch, zabbix_user_directory, name="LDAP")["changed"]
    api.userdirectory.update.assert_not_called()


@pytest.mark.parametrize("field", [
    "scim_status", "encrypt_nameid", "encrypt_assertions", "sign_messages", "sign_assertions",
    "sign_authn_requests", "sign_logout_requests", "sign_logout_responses",
])
def test_saml_flags_can_be_disabled(api, monkeypatch, field):
    api.userdirectory.get.return_value = [saml_directory(**{field: "1"})]
    assert run(monkeypatch, zabbix_user_directory, name="SAML", **{field: False})["changed"]
    api.userdirectory.update.assert_called_once_with({"userdirectoryid": "11", field: 0})


def test_provisioning_can_be_disabled_and_mappings_cleared(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(provision_status="1", provision_groups=[{"name": "old"}], provision_media=[{"name": "old"}])]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", provision_status=False, provision_groups=[], provision_media=[])["changed"]
    api.userdirectory.update.assert_called_once_with({"userdirectoryid": "10", "provision_status": 0, "provision_groups": [], "provision_media": []})


def test_media_mapping_uses_existing_provisioning_status(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(provision_status="1", provision_groups=[{"name": "existing"}])]
    api.mediatype.get.return_value = [{"mediatypeid": "1"}]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", provision_media=[
        dict(name="Mail", mediatype="Email", attribute="mail", active=False, severity=0, period="1-7,00:00-24:00")
    ])["changed"]
    mapping = api.userdirectory.update.call_args[0][0]["provision_media"][0]
    assert mapping["active"] == 1 and mapping["severity"] == 0


@pytest.mark.parametrize("field", ["idp_certificate", "sp_certificate", "sp_private_key"])
@pytest.mark.parametrize("value", ["certificate-data", ""])
def test_saml_certificates_are_compared_by_hash(api, monkeypatch, field, value):
    if field == "idp_certificate" and value == "":
        assert run(
            monkeypatch, zabbix_user_directory, name="SAML", idp_type="saml", idp_entityid="idp", sp_entityid="sp",
            sso_url="https://idp.test", username_attribute="uid", idp_certificate="",
        )["failed"]
        return
    digest = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest() if value else ""
    api.userdirectory.get.return_value = [saml_directory(**{field + "_hash": digest})]
    assert not run(monkeypatch, zabbix_user_directory, name="SAML", **{field: value})["changed"]
    api.userdirectory.update.assert_not_called()


@pytest.mark.parametrize("field", ["sp_certificate", "sp_private_key"])
def test_saml_certificate_clear(api, monkeypatch, field):
    api.userdirectory.get.return_value = [saml_directory(**{field + "_hash": "old"})]
    assert run(monkeypatch, zabbix_user_directory, name="SAML", **{field: ""})["changed"]
    api.userdirectory.update.assert_called_once_with({"userdirectoryid": "11", field: ""})


@pytest.mark.parametrize("field", ["sp_certificate", "sp_private_key"])
def test_saml_certificate_clear_requires_signing_disabled(api, monkeypatch, field):
    api.userdirectory.get.return_value = [saml_directory(sign_assertions="1", **{field + "_hash": "old"})]
    assert run(monkeypatch, zabbix_user_directory, name="SAML", **{field: ""})["failed"]
    api.userdirectory.update.assert_not_called()


def test_certificate_storage_capability_is_checked(api, monkeypatch):
    api.userdirectory.get.return_value = [saml_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="SAML", sp_certificate="data")["failed"]
    api.userdirectory.update.assert_not_called()


def test_certificate_version_is_checked(api, monkeypatch):
    api.api_version.return_value = "7.0.0"
    api.userdirectory.get.return_value = [saml_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="SAML", sp_certificate="data")["failed"]


@pytest.mark.parametrize("kwargs", [{"host": "ldaps://ldap.example.com"}, {"port": 0}, {"idp_type": "saml"}])
def test_invalid_directory_update_is_rejected(api, monkeypatch, kwargs):
    api.userdirectory.get.return_value = [ldap_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", **kwargs)["failed"]
    api.userdirectory.update.assert_not_called()


def test_directory_creation_requires_mandatory_fields(api, monkeypatch):
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", idp_type="ldap")["failed"]
    api.userdirectory.create.assert_not_called()


def test_directory_delete_needs_only_name(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", state="absent")["changed"]
    api.userdirectory.delete.assert_called_once_with(["10"])


def test_directory_check_mode(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory()]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", description="new", _ansible_check_mode=True)["changed"]
    api.userdirectory.update.assert_not_called()


def test_mfa_creation_requires_method_type(api, monkeypatch):
    assert run(monkeypatch, zabbix_mfa, name="TOTP")["failed"]
    api.mfa.create.assert_not_called()


def test_partial_totp_update_infers_type(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="TOTP", mfaid="30", type="1", hash_function="2", code_length="6")]
    assert run(monkeypatch, zabbix_mfa, name="TOTP", code_length=8)["changed"]
    assert "hash_function" not in api.mfa.update.call_args[0][0]
    assert api.mfa.update.call_args[0][0]["code_length"] == "8"


def test_duo_public_settings_are_idempotent(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="Duo", mfaid="31", type="2", api_hostname="api.example.com", clientid="client")]
    assert not run(monkeypatch, zabbix_mfa, name="Duo", api_hostname="api.example.com")["changed"]
    api.mfa.update.assert_not_called()


def test_duo_secret_is_write_only(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="Duo", mfaid="31", type="2", api_hostname="api.example.com", clientid="client")]
    assert run(monkeypatch, zabbix_mfa, name="Duo", client_secret="new-secret")["changed"]
    assert api.mfa.update.call_args[0][0]["client_secret"] == "new-secret"


@pytest.mark.parametrize("kwargs", [dict(method_type="totp"), dict(method_type="duo_universal_prompt", api_hostname="api.example.com", clientid="client")])
def test_mfa_creation_validates_required_fields(api, monkeypatch, kwargs):
    assert run(monkeypatch, zabbix_mfa, name="MFA", **kwargs)["failed"]
    api.mfa.create.assert_not_called()


def test_mfa_incompatible_options_are_rejected(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="TOTP", mfaid="30", type="1", hash_function="2", code_length="6")]
    assert run(monkeypatch, zabbix_mfa, name="TOTP", api_hostname="api.example.com")["failed"]
    api.mfa.update.assert_not_called()


def test_mfa_partial_update_check_mode(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="TOTP", mfaid="30", type="1", hash_function="2", code_length="6")]
    assert run(monkeypatch, zabbix_mfa, name="TOTP", code_length=8, _ansible_check_mode=True)["changed"]
    api.mfa.update.assert_not_called()


def test_authentication_compares_native_api_integers(api, monkeypatch):
    api.authentication.get.return_value.update(http_auth_enabled=0, passwd_check_rules=8)
    assert not run(monkeypatch, http_auth_enabled=False, passwd_check_rules=["avoid_easy_to_guess"])["changed"]
    api.authentication.update.assert_not_called()


def test_invalid_password_rule_is_rejected(api, monkeypatch):
    assert run(monkeypatch, passwd_check_rules=["invalid-rule"])["failed"]
    api.authentication.update.assert_not_called()


def test_authentication_api_failure_is_reported(api, monkeypatch):
    api.authentication.get.side_effect = Exception("API unavailable")
    result = run(monkeypatch)
    assert result["failed"] and "API unavailable" in result["msg"]


def test_cannot_clear_group_while_jit_remains_enabled(api, monkeypatch):
    api.authentication.get.return_value.update(saml_jit_status="1", disabled_usrgrpid="20")
    assert run(monkeypatch, disabled_usrgroup="")["failed"]
    api.authentication.update.assert_not_called()


def test_fuzzy_directory_match_does_not_update_another_directory(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(name="LDAP other")]
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", idp_type="ldap", host="ldap.example.com",
               port=389, base_dn="dc=example,dc=com", search_attribute="uid")["changed"]
    api.userdirectory.create.assert_called_once()
    api.userdirectory.update.assert_not_called()


def test_duplicate_provisioning_mapping_names_are_rejected(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(provision_status="1", provision_groups=[{"name": "existing"}])]
    api.mediatype.get.return_value = [{"mediatypeid": "1"}]
    mapping = dict(name="Mail", mediatype="Email", attribute="mail")
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", provision_media=[mapping, mapping])["failed"]
    api.userdirectory.update.assert_not_called()


def test_duplicate_provisioning_user_groups_are_rejected(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory(provision_status="1", provision_groups=[{"name": "existing"}])]
    mapping = dict(name="Staff", role="Guest role", user_groups=["Guests", "Guests"])
    assert run(monkeypatch, zabbix_user_directory, name="LDAP", provision_groups=[mapping])["failed"]
    api.userdirectory.update.assert_not_called()


def test_directory_api_update_failure_is_reported(api, monkeypatch):
    api.userdirectory.get.return_value = [ldap_directory()]
    api.userdirectory.update.side_effect = Exception("API unavailable")
    result = run(monkeypatch, zabbix_user_directory, name="LDAP", description="new")
    assert result["failed"] and "API unavailable" in result["msg"]


def test_totp_name_only_update_is_idempotent(api, monkeypatch):
    api.mfa.get.return_value = [dict(name="TOTP", mfaid="30", type="1", hash_function="2", code_length="6")]
    assert not run(monkeypatch, zabbix_mfa, name="TOTP")["changed"]
    api.mfa.update.assert_not_called()
