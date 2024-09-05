#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_authentication

short_description: Update Zabbix authentication

description:
   - This module allows you to modify Zabbix authentication setting.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 1.6.0

options:
    authentication_type:
        description:
            - Choose default authentication type.
        required: false
        type: str
        choices: [ "internal", "ldap" ]
    http_auth_enabled:
        description:
            - HTTP authentication will be enabled if C(true).
        required: false
        type: bool
    http_login_form:
        description:
            - Choose default login form.
        required: false
        type: str
        choices: [ "zabbix_login_form", "http_login_form" ]
    http_strip_domains:
        description:
            - A list of domain names that should be removed from the username.
        required: false
        type: list
        elements: str
    http_case_sensitive:
        description:
            - Case sensitive login for HTTP authentication will be enabled if C(true).
        required: false
        type: bool
    ldap_configured:
        description:
            - LDAP authentication will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
            - Removed in Zabbix 6.4
        required: false
        type: bool
    ldap_auth_enabled:
        description:
            - LDAP authentication will be enabled if C(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    ldap_host:
        description:
            - LDAP server name.
            - e.g. C(ldap://ldap.zabbix.com)
            - This setting is required if current value of I(ldap_configured) is C(false).
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: str
    ldap_port:
        description:
            - A port number of LDAP server.
            - This setting is required if current value of I(ldap_configured) is C(false).
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: int
    ldap_base_dn:
        description:
            - Base DN of LDAP.
            - This setting is required if current value of I(ldap_configured) is C(false).
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: str
    ldap_search_attribute:
        description:
            - Search attribute of LDAP.
            - This setting is required if current value of I(ldap_configured) is C(false).
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: str
    ldap_bind_dn:
        description:
            - Bind DN of LDAP.
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: str
    ldap_case_sensitive:
        description:
            - case sensitive login for LDAP authentication will be enabled if C(true).
        required: false
        type: bool
    ldap_bind_password:
        description:
            - Bind password of LDAP.
            - Works only with Zabbix <= 6.0 and is silently ignored in higher versions.
        required: false
        type: str
    ldap_userdirectory:
        description:
            - LDAP authentication default user directory name for user groups with gui_access set to LDAP or System default.
            - Required to be set when C(ldap_configured) / C(ldap_auth_enabled) is set to 1.
        required: false
        type: str
    ldap_jit_status:
        description:
            - Status of LDAP provisioning.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    jit_provision_interval:
        description:
            - Time interval between JIT provision requests for logged-in user.
            - Accepts seconds and time unit with suffix with month and year support (3600s,60m,1h,1d,1M,1y). Minimum value 1h.
            - Available only for LDAP provisioning.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
        default: 1h
    disabled_usrgroup:
        description:
            - User group name to assign the deprovisioned user to.
            - The user group must be disabled and cannot be enabled or deleted when configured.
            - Required if C(ldap_jit_status) for C(saml_jit_status) enabled.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    saml_auth_enabled:
        description:
            - SAML authentication will be enabled if C(true).
        required: false
        type: bool
    saml_idp_entityid:
        description:
            - SAML identify provider's entity ID.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_sso_url:
        description:
            - URL for single sign on service of SAML.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_slo_url:
        description:
            - URL for SAML single logout service.
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_username_attribute:
        description:
            - User name attribute of SAML.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_sp_entityid:
        description:
            - Entity ID of SAML service provider.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_nameid_format:
        description:
            - Name identifier format of SAML service provider.
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: str
    saml_sign_messages:
        description:
            - SAML sign messages will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_sign_assertions:
        description:
            - SAML sign assertions will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_sign_authn_requests:
        description:
            - SAML sign AuthN requests will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_sign_logout_requests:
        description:
            - SAML sign logout requests will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_sign_logout_responses:
        description:
            - SAML sign logout responses will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_encrypt_nameid:
        description:
            - SAML encrypt name ID will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_encrypt_assertions:
        description:
            - SAML encrypt assertions will be enabled if C(true).
            - Works only with Zabbix <= 6.2 and is silently ignored in higher versions.
        required: false
        type: bool
    saml_case_sensitive:
        description:
            - Case sensitive login for SAML authentication will be enabled if C(true).
        required: false
        type: bool
    saml_jit_status:
        description:
            - Status of SAML provisioning.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    passwd_min_length:
        description:
            - Minimal length of password.
            - Choose from 1-70.
            - This parameter is available since Zabbix 6.0.
        required: false
        type: int
    passwd_check_rules:
        description:
            - Checking password rules.
            - Select multiple from C(contain_uppercase_and_lowercase_letters),
              C(contain_digits). C(contain_special_characters) and C(avoid_easy_to_guess).
            - This parameter is available since Zabbix 6.0.
        required: false
        type: list
        elements: str

extends_documentation_fragment:
    - community.zabbix.zabbix
"""

EXAMPLES = """
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  ansible.builtin.set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  ansible.builtin.set_fact:
    ansible_zabbix_auth_key: 8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895

- name: Update all authentication setting (Zabbix <= 6.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_authentication:
    authentication_type: internal
    http_auth_enabled: true
    http_login_form: zabbix_login_form
    http_strip_domains:
      - comp
      - any
    http_case_sensitive: true
    ldap_configured: true
    ldap_host: "ldap://localhost"
    ldap_port: 389
    ldap_base_dn: "ou=Users,ou=system"
    ldap_search_attribute: "uid"
    ldap_bind_dn: "uid=ldap_search,ou=system"
    ldap_case_sensitive: true
    ldap_bind_password: "password"
    saml_auth_enabled: true
    saml_idp_entityid: ""
    saml_sso_url: "https://localhost/SAML2/SSO"
    saml_slo_url: "https://localhost/SAML2/SLO"
    saml_username_attribute: "uid"
    saml_sp_entityid: "https://localhost"
    saml_nameid_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    saml_sign_messages: true
    saml_sign_assertions: true
    saml_sign_authn_requests: true
    saml_sign_logout_requests: true
    saml_sign_logout_responses: true
    saml_encrypt_nameid: true
    saml_encrypt_assertions: true
    saml_case_sensitive: true
    passwd_min_length: 70
    passwd_check_rules:
      - contain_uppercase_and_lowercase_letters
      - contain_digits
      - contain_special_characters
      - avoid_easy_to_guess

- name: Update all authentication setting (Zabbix = 6.2)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_authentication:
    authentication_type: internal
    http_auth_enabled: true
    http_login_form: zabbix_login_form
    http_strip_domains:
      - comp
      - any
    http_case_sensitive: true
    ldap_configured: true
    ldap_case_sensitive: true
    saml_auth_enabled: true
    saml_idp_entityid: ""
    saml_sso_url: "https://localhost/SAML2/SSO"
    saml_slo_url: "https://localhost/SAML2/SLO"
    saml_username_attribute: "uid"
    saml_sp_entityid: "https://localhost"
    saml_nameid_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    saml_sign_messages: true
    saml_sign_assertions: true
    saml_sign_authn_requests: true
    saml_sign_logout_requests: true
    saml_sign_logout_responses: true
    saml_encrypt_nameid: true
    saml_encrypt_assertions: true
    saml_case_sensitive: true
    passwd_min_length: 70
    passwd_check_rules:
      - contain_uppercase_and_lowercase_letters
      - contain_digits
      - contain_special_characters
      - avoid_easy_to_guess

- name: Update all authentication setting (Zabbix >= 6.4)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_authentication:
    authentication_type: internal
    http_auth_enabled: true
    http_login_form: zabbix_login_form
    http_strip_domains:
      - comp
      - any
    http_case_sensitive: true
    ldap_auth_enabled: true
    ldap_userdirectory: TestUserDirectory
    ldap_case_sensitive: true
    saml_auth_enabled: true
    saml_case_sensitive: true
    ldap_jit_status: true
    saml_jit_status: true
    jit_provision_interval: 1h
    disabled_usrgrp: Disabled
    passwd_min_length: 70
    passwd_check_rules:
      - contain_uppercase_and_lowercase_letters
      - contain_digits
      - contain_special_characters
      - avoid_easy_to_guess
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: "Successfully update authentication setting"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Authentication(ZabbixBase):

    # get authentication setting
    def get_authentication(self):
        try:
            return self._zapi.authentication.get({"output": "extend"})
        except Exception as e:
            self._module.fail_json(msg="Failed to get authentication setting: %s" % e)

    # update authentication setting
    def update_authentication(
        self,
        current_authentication,
        authentication_type,
        http_auth_enabled,
        http_login_form,
        http_strip_domains,
        http_case_sensitive,
        ldap_configured,
        ldap_auth_enabled,
        ldap_host,
        ldap_port,
        ldap_base_dn,
        ldap_search_attribute,
        ldap_bind_dn,
        ldap_case_sensitive,
        ldap_bind_password,
        ldap_userdirectory,
        saml_auth_enabled,
        saml_idp_entityid,
        saml_sso_url,
        saml_slo_url,
        saml_username_attribute,
        saml_sp_entityid,
        saml_nameid_format,
        saml_sign_messages,
        saml_sign_assertions,
        saml_sign_authn_requests,
        saml_sign_logout_requests,
        saml_sign_logout_responses,
        saml_encrypt_nameid,
        saml_encrypt_assertions,
        saml_case_sensitive,
        passwd_min_length,
        passwd_check_rules,
        ldap_jit_status,
        saml_jit_status,
        jit_provision_interval,
        disabled_usrgroup,
    ):
        try:
            params = {}

            if authentication_type:
                params["authentication_type"] = str(
                    zabbix_utils.helper_to_numeric_value(
                        ["internal", "ldap"], authentication_type
                    )
                )

            if isinstance(http_auth_enabled, bool):
                params["http_auth_enabled"] = str(int(http_auth_enabled))

            if http_login_form:
                params["http_login_form"] = str(
                    zabbix_utils.helper_to_numeric_value(
                        ["zabbix_login_form", "http_login_form"], http_login_form
                    )
                )

            if http_strip_domains:
                params["http_strip_domains"] = ",".join(http_strip_domains)

            if isinstance(http_case_sensitive, bool):
                params["http_case_sensitive"] = str(int(http_case_sensitive))

            if LooseVersion(self._zbx_api_version) < LooseVersion("6.4"):
                if isinstance(ldap_configured, bool):
                    params["ldap_configured"] = str(int(ldap_configured))
            else:
                if isinstance(ldap_auth_enabled, bool):
                    params["ldap_auth_enabled"] = str(int(ldap_auth_enabled))

            if LooseVersion(self._zbx_api_version) < LooseVersion("6.2"):
                if ldap_host:
                    params["ldap_host"] = ldap_host

                if ldap_port:
                    params["ldap_port"] = str(ldap_port)

                if ldap_base_dn:
                    params["ldap_base_dn"] = ldap_base_dn

                if ldap_search_attribute:
                    params["ldap_search_attribute"] = ldap_search_attribute

                if ldap_bind_dn:
                    params["ldap_bind_dn"] = ldap_bind_dn

                if ldap_bind_password:
                    params["ldap_bind_password"] = ldap_bind_password
            else:
                if ldap_userdirectory:
                    directory = self._zapi.userdirectory.get(
                        {"search": {"name": ldap_userdirectory}}
                    )
                    if not directory:
                        self._module.fail_json(
                            msg="Canot find user directory with name: %s"
                            % ldap_userdirectory
                        )
                    params["ldap_userdirectoryid"] = directory[0]["userdirectoryid"]

            if isinstance(ldap_case_sensitive, bool):
                params["ldap_case_sensitive"] = str(int(ldap_case_sensitive))

            if isinstance(saml_auth_enabled, bool):
                params["saml_auth_enabled"] = str(int(saml_auth_enabled))

            if LooseVersion(self._zbx_api_version) < LooseVersion("6.4"):
                if saml_idp_entityid:
                    params["saml_idp_entityid"] = saml_idp_entityid

                if saml_sso_url:
                    params["saml_sso_url"] = saml_sso_url

                if saml_slo_url:
                    params["saml_slo_url"] = saml_slo_url

                if saml_username_attribute:
                    params["saml_username_attribute"] = saml_username_attribute

                if saml_sp_entityid:
                    params["saml_sp_entityid"] = saml_sp_entityid

                if saml_nameid_format:
                    params["saml_nameid_format"] = saml_nameid_format

                if isinstance(saml_sign_messages, bool):
                    params["saml_sign_messages"] = str(int(saml_sign_messages))

                if isinstance(saml_sign_assertions, bool):
                    params["saml_sign_assertions"] = str(int(saml_sign_assertions))

                if isinstance(saml_sign_authn_requests, bool):
                    params["saml_sign_authn_requests"] = str(
                        int(saml_sign_authn_requests)
                    )

                if isinstance(saml_sign_logout_requests, bool):
                    params["saml_sign_logout_requests"] = str(
                        int(saml_sign_logout_requests)
                    )

                if isinstance(saml_sign_logout_responses, bool):
                    params["saml_sign_logout_responses"] = str(
                        int(saml_sign_logout_responses)
                    )

                if isinstance(saml_encrypt_nameid, bool):
                    params["saml_encrypt_nameid"] = str(int(saml_encrypt_nameid))

                if isinstance(saml_encrypt_assertions, bool):
                    params["saml_encrypt_assertions"] = str(
                        int(saml_encrypt_assertions)
                    )

                if isinstance(saml_case_sensitive, bool):
                    params["saml_case_sensitive"] = str(int(saml_case_sensitive))
            else:
                if isinstance(ldap_jit_status, bool):
                    params["ldap_jit_status"] = str(int(ldap_jit_status))

                if isinstance(saml_jit_status, bool):
                    params["saml_jit_status"] = str(int(saml_jit_status))

                if isinstance(jit_provision_interval, str):
                    params["jit_provision_interval"] = jit_provision_interval

                if isinstance(disabled_usrgroup, str):
                    usrgrpids = self._zapi.usergroup.get(
                        {"filter": {"name": disabled_usrgroup}}
                    )
                    if not usrgrpids:
                        self._module.fail_json(
                            "User group '%s' cannot be found" % disabled_usrgroup
                        )
                    params["disabled_usrgrpid"] = str(int(usrgrpids[0]["usrgrpid"]))

                if (ldap_jit_status or saml_jit_status) and not disabled_usrgroup:
                    self._module.fail_json(
                        "'disabled_usrgroup' must be provided if 'ldap_jit_status' or 'saml_jit_status' enabled"
                    )

            if passwd_min_length:
                if passwd_min_length < 1 or passwd_min_length > 70:
                    self._module.fail_json(msg="Please set 0-70 to passwd_min_length.")
                else:
                    params["passwd_min_length"] = str(passwd_min_length)

            if passwd_check_rules is not None:
                passwd_check_rules_values = [
                    "contain_uppercase_and_lowercase_letters",
                    "contain_digits",
                    "contain_special_characters",
                    "avoid_easy_to_guess",
                ]
                params["passwd_check_rules"] = 0
                if isinstance(passwd_check_rules, str):
                    if passwd_check_rules not in passwd_check_rules_values:
                        self._module.fail_json(
                            msg="%s is invalid value for passwd_check_rules."
                            % passwd_check_rules
                        )
                    params[
                        "passwd_check_rules"
                    ] += 2 ** zabbix_utils.helper_to_numeric_value(
                        passwd_check_rules_values, passwd_check_rules
                    )
                elif isinstance(passwd_check_rules, list):
                    for _passwd_check_rules_value in passwd_check_rules:
                        if (
                            _passwd_check_rules_value
                            not in passwd_check_rules_values
                        ):
                            self._module.fail_json(
                                msg="%s is invalid value for passwd_check_rules."
                                % _passwd_check_rules_value
                            )
                        params[
                            "passwd_check_rules"
                        ] += 2 ** zabbix_utils.helper_to_numeric_value(
                            passwd_check_rules_values, _passwd_check_rules_value
                        )

                params["passwd_check_rules"] = str(params["passwd_check_rules"])

            future_authentication = current_authentication.copy()
            future_authentication.update(params)

            if LooseVersion(self._zbx_api_version) < LooseVersion("6.4"):
                if (
                    current_authentication["ldap_configured"] == "0"
                    and future_authentication["ldap_configured"] == "1"
                ):
                    if LooseVersion(self._zbx_api_version) < LooseVersion("6.2"):
                        if (
                            not ldap_host
                            or not ldap_port
                            or not ldap_search_attribute
                            or not ldap_base_dn
                        ):
                            self._module.fail_json(
                                msg="Please set ldap_host, ldap_search_attribute and ldap_base_dn when you change a value of ldap_configured to true."
                            )
                    else:
                        if not ldap_userdirectory:
                            self._module.fail_json(
                                msg="Please set ldap_userdirectory when you change a value of ldap_configured to true."
                            )
            else:
                if (
                    current_authentication["ldap_auth_enabled"] == "0"
                    and future_authentication["ldap_auth_enabled"] == "1"
                ):
                    if not ldap_userdirectory:
                        self._module.fail_json(
                            msg="Please set ldap_userdirectory when you change a value of ldap_auth_enabled to true."
                        )

            if LooseVersion(self._zbx_api_version) < LooseVersion("6.4"):
                if (
                    current_authentication["saml_auth_enabled"] == "0"
                    and future_authentication["saml_auth_enabled"] == "1"
                    and not saml_idp_entityid
                    and not saml_sso_url
                    and not saml_username_attribute
                    and not saml_sp_entityid
                ):
                    self._module.fail_json(
                        msg=" ".join(
                            [
                                "Please set saml_idp_entityid, saml_sso_url, saml_username_attribute and saml_sp_entityid",
                                "when you change a value of saml_auth_enabled to true.",
                            ]
                        )
                    )

            if future_authentication != current_authentication:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)

                self._zapi.authentication.update(params)
                self._module.exit_json(
                    changed=True, result="Successfully update authentication setting"
                )
            else:
                self._module.exit_json(
                    changed=False, result="Authentication setting is already up to date"
                )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to update authentication setting, Exception: %s" % e
            )


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            authentication_type=dict(type="str", choices=["internal", "ldap"]),
            http_auth_enabled=dict(type="bool"),
            http_login_form=dict(
                type="str", choices=["zabbix_login_form", "http_login_form"]
            ),
            http_strip_domains=dict(type="list", elements="str"),
            http_case_sensitive=dict(type="bool"),
            ldap_configured=dict(type="bool"),
            ldap_auth_enabled=dict(type="bool"),
            ldap_host=dict(type="str"),
            ldap_port=dict(type="int"),
            ldap_base_dn=dict(type="str"),
            ldap_search_attribute=dict(type="str"),
            ldap_bind_dn=dict(type="str"),
            ldap_case_sensitive=dict(type="bool"),
            ldap_bind_password=dict(type="str", no_log=True),
            ldap_userdirectory=dict(type="str"),
            ldap_jit_status=dict(type="bool"),
            saml_auth_enabled=dict(type="bool"),
            saml_idp_entityid=dict(type="str"),
            saml_sso_url=dict(type="str"),
            saml_slo_url=dict(type="str"),
            saml_username_attribute=dict(type="str"),
            saml_sp_entityid=dict(type="str"),
            saml_nameid_format=dict(type="str"),
            saml_sign_messages=dict(type="bool"),
            saml_sign_assertions=dict(type="bool"),
            saml_sign_authn_requests=dict(type="bool"),
            saml_sign_logout_requests=dict(type="bool"),
            saml_sign_logout_responses=dict(type="bool"),
            saml_encrypt_nameid=dict(type="bool"),
            saml_encrypt_assertions=dict(type="bool"),
            saml_case_sensitive=dict(type="bool"),
            saml_jit_status=dict(type="bool"),
            jit_provision_interval=dict(type="str", default="1h"),
            disabled_usrgroup=dict(type="str"),
            passwd_min_length=dict(type="int", no_log=False),
            passwd_check_rules=dict(type="list", elements="str", no_log=False),
        )
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    authentication_type = module.params["authentication_type"]
    http_auth_enabled = module.params["http_auth_enabled"]
    http_login_form = module.params["http_login_form"]
    http_strip_domains = module.params["http_strip_domains"]
    http_case_sensitive = module.params["http_case_sensitive"]
    ldap_configured = module.params["ldap_configured"]
    ldap_auth_enabled = module.params["ldap_auth_enabled"]
    ldap_host = module.params["ldap_host"]
    ldap_port = module.params["ldap_port"]
    ldap_base_dn = module.params["ldap_base_dn"]
    ldap_search_attribute = module.params["ldap_search_attribute"]
    ldap_bind_dn = module.params["ldap_bind_dn"]
    ldap_case_sensitive = module.params["ldap_case_sensitive"]
    ldap_bind_password = module.params["ldap_bind_password"]
    ldap_userdirectory = module.params["ldap_userdirectory"]
    saml_auth_enabled = module.params["saml_auth_enabled"]
    saml_idp_entityid = module.params["saml_idp_entityid"]
    saml_sso_url = module.params["saml_sso_url"]
    saml_slo_url = module.params["saml_slo_url"]
    saml_username_attribute = module.params["saml_username_attribute"]
    saml_sp_entityid = module.params["saml_sp_entityid"]
    saml_nameid_format = module.params["saml_nameid_format"]
    saml_sign_messages = module.params["saml_sign_messages"]
    saml_sign_assertions = module.params["saml_sign_assertions"]
    saml_sign_authn_requests = module.params["saml_sign_authn_requests"]
    saml_sign_logout_requests = module.params["saml_sign_logout_requests"]
    saml_sign_logout_responses = module.params["saml_sign_logout_responses"]
    saml_encrypt_nameid = module.params["saml_encrypt_nameid"]
    saml_encrypt_assertions = module.params["saml_encrypt_assertions"]
    saml_case_sensitive = module.params["saml_case_sensitive"]
    passwd_min_length = module.params["passwd_min_length"]
    passwd_check_rules = module.params["passwd_check_rules"]
    ldap_jit_status = module.params["ldap_jit_status"]
    saml_jit_status = module.params["saml_jit_status"]
    jit_provision_interval = module.params["jit_provision_interval"]
    disabled_usrgroup = module.params["disabled_usrgroup"]

    authentication = Authentication(module)

    current_authentication = authentication.get_authentication()
    authentication.update_authentication(
        current_authentication,
        authentication_type,
        http_auth_enabled,
        http_login_form,
        http_strip_domains,
        http_case_sensitive,
        ldap_configured,
        ldap_auth_enabled,
        ldap_host,
        ldap_port,
        ldap_base_dn,
        ldap_search_attribute,
        ldap_bind_dn,
        ldap_case_sensitive,
        ldap_bind_password,
        ldap_userdirectory,
        saml_auth_enabled,
        saml_idp_entityid,
        saml_sso_url,
        saml_slo_url,
        saml_username_attribute,
        saml_sp_entityid,
        saml_nameid_format,
        saml_sign_messages,
        saml_sign_assertions,
        saml_sign_authn_requests,
        saml_sign_logout_requests,
        saml_sign_logout_responses,
        saml_encrypt_nameid,
        saml_encrypt_assertions,
        saml_case_sensitive,
        passwd_min_length,
        passwd_check_rules,
        ldap_jit_status,
        saml_jit_status,
        jit_provision_interval,
        disabled_usrgroup,
    )


if __name__ == "__main__":
    main()
