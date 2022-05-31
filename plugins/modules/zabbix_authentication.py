#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_authentication

short_description: Update Zabbix authentication

description:
   - This module allows you to modify Zabbix authentication setting.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "zabbix-api >= 0.5.4"

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
        required: false
        type: bool
    ldap_host:
        description:
            - LDAP server name.
            - e.g. C(ldap://ldap.zabbix.com)
            - This setting is required if current value of I(ldap_configured) is C(false).
        required: false
        type: str
    ldap_port:
        description:
            - A port number of LDAP server.
            - This setting is required if current value of I(ldap_configured) is C(false).
        required: false
        type: int
    ldap_base_dn:
        description:
            - Base DN of LDAP.
            - This setting is required if current value of I(ldap_configured) is C(false).
        required: false
        type: str
    ldap_search_attribute:
        description:
            - Search attribute of LDAP.
            - This setting is required if current value of I(ldap_configured) is C(false).
        required: false
        type: str
    ldap_bind_dn:
        description:
            - Bind DN of LDAP.
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
        required: false
        type: str
    saml_sso_url:
        description:
            - URL for single sign on service of SAML.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
        required: false
        type: str
    saml_slo_url:
        description:
            - URL for SAML single logout service.
        required: false
        type: str
    saml_username_attribute:
        description:
            - User name attribute of SAML.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
        required: false
        type: str
    saml_sp_entityid:
        description:
            - Entity ID of SAML service provider.
            - This setting is required if current value of I(saml_auth_enabled) is C(false).
        required: false
        type: str
    saml_nameid_format:
        description:
            - Name identifier format of SAML service provider.
        required: false
        type: str
    saml_sign_messages:
        description:
            - SAML sign messages will be enabled if C(true).
        required: false
        type: bool
    saml_sign_assertions:
        description:
            - SAML sign assertions will be enabled if C(true).
        required: false
        type: bool
    saml_sign_authn_requests:
        description:
            - SAML sign AuthN requests will be enabled if C(true).
        required: false
        type: bool
    saml_sign_logout_requests:
        description:
            - SAML sign logout requests will be enabled if C(true).
        required: false
        type: bool
    saml_sign_logout_responses:
        description:
            - SAML sign logout responses will be enabled if C(true).
        required: false
        type: bool
    saml_encrypt_nameid:
        description:
            - SAML encrypt name ID will be enabled if C(true).
        required: false
        type: bool
    saml_encrypt_assertions:
        description:
            - SAML encrypt assertions will be enabled if C(true).
        required: false
        type: bool
    saml_case_sensitive:
        description:
            - Case sensitive login for SAML authentication will be enabled if C(true).
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

notes:
    - Zabbix 5.4 version and higher are supported.

extends_documentation_fragment:
    - community.zabbix.zabbix
'''

EXAMPLES = '''
- name: Update all authentication setting
  zabbix_authentication:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
    authentication_type: internal
    http_auth_enabled: true
    http_login_form: zabbix_login_form
    http_strip_domains:
      - comp
      - any
    http_case_sensitive: true
    ldap_configured: true
    ldap_host: 'ldap://localhost'
    ldap_port: 389
    ldap_base_dn: 'ou=Users,ou=system'
    ldap_search_attribute: 'uid'
    ldap_bind_dn: 'uid=ldap_search,ou=system'
    ldap_case_sensitive: true
    ldap_bind_password: 'password'
    saml_auth_enabled: true
    saml_idp_entityid: ''
    saml_sso_url: 'https://localhost/SAML2/SSO'
    saml_slo_url: 'https://localhost/SAML2/SLO'
    saml_username_attribute: 'uid'
    saml_sp_entityid: 'https://localhost'
    saml_nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
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
'''

RETURN = '''
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: 'Successfully update authentication setting'
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Authentication(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(Authentication, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion('5.4.0'):
            module.fail_json(msg="This module doesn't support Zabbix versions lower than 5.4.0")

    # get authentication setting
    def get_authentication(self):
        try:
            return self._zapi.authentication.get({'output': 'extend'})
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
            ldap_host,
            ldap_port,
            ldap_base_dn,
            ldap_search_attribute,
            ldap_bind_dn,
            ldap_case_sensitive,
            ldap_bind_password,
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
            passwd_check_rules):
        try:
            params = {}

            if authentication_type:
                params['authentication_type'] = str(zabbix_utils.helper_to_numeric_value(
                    ['internal', 'ldap'],
                    authentication_type
                ))

            if isinstance(http_auth_enabled, bool):
                params['http_auth_enabled'] = str(int(http_auth_enabled))

            if http_login_form:
                params['http_login_form'] = str(zabbix_utils.helper_to_numeric_value(
                    ['zabbix_login_form', 'http_login_form'],
                    http_login_form
                ))

            if http_strip_domains:
                params['http_strip_domains'] = ','.join(http_strip_domains)

            if isinstance(http_case_sensitive, bool):
                params['http_case_sensitive'] = str(int(http_case_sensitive))

            if isinstance(ldap_configured, bool):
                params['ldap_configured'] = str(int(ldap_configured))

            if ldap_host:
                params['ldap_host'] = ldap_host

            if ldap_port:
                params['ldap_port'] = str(ldap_port)

            if ldap_base_dn:
                params['ldap_base_dn'] = ldap_base_dn

            if ldap_search_attribute:
                params['ldap_search_attribute'] = ldap_search_attribute

            if ldap_bind_dn:
                params['ldap_bind_dn'] = ldap_bind_dn

            if isinstance(ldap_case_sensitive, bool):
                params['ldap_case_sensitive'] = str(int(ldap_case_sensitive))

            if ldap_bind_password:
                params['ldap_bind_password'] = ldap_bind_password

            if isinstance(saml_auth_enabled, bool):
                params['saml_auth_enabled'] = str(int(saml_auth_enabled))

            if saml_idp_entityid:
                params['saml_idp_entityid'] = saml_idp_entityid

            if saml_sso_url:
                params['saml_sso_url'] = saml_sso_url

            if saml_slo_url:
                params['saml_slo_url'] = saml_slo_url

            if saml_username_attribute:
                params['saml_username_attribute'] = saml_username_attribute

            if saml_sp_entityid:
                params['saml_sp_entityid'] = saml_sp_entityid

            if saml_nameid_format:
                params['saml_nameid_format'] = saml_nameid_format

            if isinstance(saml_sign_messages, bool):
                params['saml_sign_messages'] = str(int(saml_sign_messages))

            if isinstance(saml_sign_assertions, bool):
                params['saml_sign_assertions'] = str(int(saml_sign_assertions))

            if isinstance(saml_sign_authn_requests, bool):
                params['saml_sign_authn_requests'] = str(int(saml_sign_authn_requests))

            if isinstance(saml_sign_logout_requests, bool):
                params['saml_sign_logout_requests'] = str(int(saml_sign_logout_requests))

            if isinstance(saml_sign_logout_responses, bool):
                params['saml_sign_logout_responses'] = str(int(saml_sign_logout_responses))

            if isinstance(saml_encrypt_nameid, bool):
                params['saml_encrypt_nameid'] = str(int(saml_encrypt_nameid))

            if isinstance(saml_encrypt_assertions, bool):
                params['saml_encrypt_assertions'] = str(int(saml_encrypt_assertions))

            if isinstance(saml_case_sensitive, bool):
                params['saml_case_sensitive'] = str(int(saml_case_sensitive))

            if passwd_min_length:
                if LooseVersion(self._zbx_api_version) < LooseVersion('6.0'):
                    self._module.warn('passwd_min_length is ignored with Zabbix 5.4.')
                elif passwd_min_length < 1 or passwd_min_length > 70:
                    self._module.fail_json(msg="Please set 0-70 to passwd_min_length.")
                else:
                    params['passwd_min_length'] = str(passwd_min_length)

            if passwd_check_rules:
                if LooseVersion(self._zbx_api_version) < LooseVersion('6.0'):
                    self._module.warn('passwd_check_rules is ignored with Zabbix 5.4.')
                else:
                    passwd_check_rules_values = [
                        'contain_uppercase_and_lowercase_letters',
                        'contain_digits',
                        'contain_special_characters',
                        'avoid_easy_to_guess'
                    ]
                    params['passwd_check_rules'] = 0
                    if isinstance(passwd_check_rules, str):
                        if passwd_check_rules not in passwd_check_rules_values:
                            self._module.fail_json(msg="%s is invalid value for passwd_check_rules." % passwd_check_rules)
                        params['passwd_check_rules'] += 2 ** zabbix_utils.helper_to_numeric_value(
                            passwd_check_rules_values, passwd_check_rules
                        )
                    elif isinstance(passwd_check_rules, list):
                        for _passwd_check_rules_value in passwd_check_rules:
                            if _passwd_check_rules_value not in passwd_check_rules_values:
                                self._module.fail_json(msg="%s is invalid value for passwd_check_rules." % _passwd_check_rules_value)
                            params['passwd_check_rules'] += 2 ** zabbix_utils.helper_to_numeric_value(
                                passwd_check_rules_values, _passwd_check_rules_value
                            )

                    params['passwd_check_rules'] = str(params['passwd_check_rules'])

            future_authentication = current_authentication.copy()
            future_authentication.update(params)

            if (current_authentication['ldap_configured'] == '0'
                    and future_authentication['ldap_configured'] == '1'
                    and not ldap_host
                    and not ldap_port
                    and not ldap_search_attribute
                    and not ldap_base_dn):
                self._module.fail_json(
                    msg="Please set ldap_host, ldap_search_attribute and ldap_base_dn when you change a value of ldap_configured to true."
                )

            if (current_authentication['saml_auth_enabled'] == '0'
                    and future_authentication['saml_auth_enabled'] == '1'
                    and not saml_idp_entityid
                    and not saml_sso_url
                    and not saml_username_attribute
                    and not saml_sp_entityid):
                self._module.fail_json(
                    msg=' '.join([
                        "Please set saml_idp_entityid, saml_sso_url, saml_username_attribute and saml_sp_entityid",
                        "when you change a value of saml_auth_enabled to true."
                    ])
                )

            if future_authentication != current_authentication:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)

                self._zapi.authentication.update(params)
                self._module.exit_json(changed=True, result="Successfully update authentication setting")
            else:
                self._module.exit_json(changed=False, result="Authentication setting is already up to date")
        except Exception as e:
            self._module.fail_json(msg="Failed to update authentication setting, Exception: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        authentication_type=dict(type='str', choices=['internal', 'ldap']),
        http_auth_enabled=dict(type='bool'),
        http_login_form=dict(type='str', choices=['zabbix_login_form', 'http_login_form']),
        http_strip_domains=dict(type='list', elements='str'),
        http_case_sensitive=dict(type='bool'),
        ldap_configured=dict(type='bool'),
        ldap_host=dict(type='str'),
        ldap_port=dict(type='int'),
        ldap_base_dn=dict(type='str'),
        ldap_search_attribute=dict(type='str'),
        ldap_bind_dn=dict(type='str'),
        ldap_case_sensitive=dict(type='bool'),
        ldap_bind_password=dict(type='str', no_log=True),
        saml_auth_enabled=dict(type='bool'),
        saml_idp_entityid=dict(type='str'),
        saml_sso_url=dict(type='str'),
        saml_slo_url=dict(type='str'),
        saml_username_attribute=dict(type='str'),
        saml_sp_entityid=dict(type='str'),
        saml_nameid_format=dict(type='str'),
        saml_sign_messages=dict(type='bool'),
        saml_sign_assertions=dict(type='bool'),
        saml_sign_authn_requests=dict(type='bool'),
        saml_sign_logout_requests=dict(type='bool'),
        saml_sign_logout_responses=dict(type='bool'),
        saml_encrypt_nameid=dict(type='bool'),
        saml_encrypt_assertions=dict(type='bool'),
        saml_case_sensitive=dict(type='bool'),
        passwd_min_length=dict(type='int', no_log=False),
        passwd_check_rules=dict(type='list', elements='str', no_log=False)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    authentication_type = module.params['authentication_type']
    http_auth_enabled = module.params['http_auth_enabled']
    http_login_form = module.params['http_login_form']
    http_strip_domains = module.params['http_strip_domains']
    http_case_sensitive = module.params['http_case_sensitive']
    ldap_configured = module.params['ldap_configured']
    ldap_host = module.params['ldap_host']
    ldap_port = module.params['ldap_port']
    ldap_base_dn = module.params['ldap_base_dn']
    ldap_search_attribute = module.params['ldap_search_attribute']
    ldap_bind_dn = module.params['ldap_bind_dn']
    ldap_case_sensitive = module.params['ldap_case_sensitive']
    ldap_bind_password = module.params['ldap_bind_password']
    saml_auth_enabled = module.params['saml_auth_enabled']
    saml_idp_entityid = module.params['saml_idp_entityid']
    saml_sso_url = module.params['saml_sso_url']
    saml_slo_url = module.params['saml_slo_url']
    saml_username_attribute = module.params['saml_username_attribute']
    saml_sp_entityid = module.params['saml_sp_entityid']
    saml_nameid_format = module.params['saml_nameid_format']
    saml_sign_messages = module.params['saml_sign_messages']
    saml_sign_assertions = module.params['saml_sign_assertions']
    saml_sign_authn_requests = module.params['saml_sign_authn_requests']
    saml_sign_logout_requests = module.params['saml_sign_logout_requests']
    saml_sign_logout_responses = module.params['saml_sign_logout_responses']
    saml_encrypt_nameid = module.params['saml_encrypt_nameid']
    saml_encrypt_assertions = module.params['saml_encrypt_assertions']
    saml_case_sensitive = module.params['saml_case_sensitive']
    passwd_min_length = module.params['passwd_min_length']
    passwd_check_rules = module.params['passwd_check_rules']

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
        ldap_host,
        ldap_port,
        ldap_base_dn,
        ldap_search_attribute,
        ldap_bind_dn,
        ldap_case_sensitive,
        ldap_bind_password,
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
        passwd_check_rules
    )


if __name__ == '__main__':
    main()
