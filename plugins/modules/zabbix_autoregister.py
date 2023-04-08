#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_autoregister

short_description: Update Zabbix autoregistration


description:
    - This module allows you to modify Zabbix autoregistration.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 2.6"

version_added: 1.6.0

options:
    tls_accept:
        description:
            - Type of allowed incoming connections for autoregistration.
            - Choose from C(unsecure), C(tls_with_psk) or both.
        type: list
        elements: str
        required: true
    tls_psk_identity:
        description:
            - TLS connection uses this PSK identity string.
            - The PSK identity string will be transmitted unencrypted over the network. Therefore, you should not put any sensitive information here.
            - This setting requires I(tls_accept=tls_with_psk) if current value of I(tls_accept) is C(unsecure).
        type: str
    tls_psk:
        description:
            - TLS connection uses this PSK value.
            - This setting requires I(tls_accept=tls_with_psk) if current value of I(tls_accept) is C(unsecure).
        type: str

notes:
    - Only Zabbix >= 4.4 is supported.
    - This module returns changed=true when any value is set in I(tls_psk_identity) or I(tls_psk) as Zabbix API
      will not return any sensitive information back for module to compare.
    - Please note that this module configures B(global Zabbix Server settings).
      If you want to create autoregistration action so your hosts can automatically add themselves
      to the monitoring have a look at M(community.zabbix.zabbix_action).

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = '''
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  set_fact:
    ansible_zabbix_auth_key: 8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895

- name: Update autoregistration
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_autoregister:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
    tls_accept:
      - unsecure
      - tls_with_psk
    tls_psk_identity: 'PSK 001'
    tls_psk: "11111595725ac58dd977beef14b97461a7c1045b9a1c923453302c5473193478"

- name: Set unsecure to tls_accept
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_autoregister:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
    tls_accept: unsecure
'''

RETURN = '''
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: 'Successfully updated global autoregistration setting'
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Autoregistration(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(Autoregistration, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion('4.4.0'):
            module.fail_json(msg="This module doesn't support Zabbix versions lower than 4.4.0")

    # get autoregistration
    def get_autoregistration(self):
        try:
            return self._zapi.autoregistration.get({"output": 'extend'})
        except Exception as e:
            self._module.fail_json(msg="Failed to get autoregistration: %s" % e)

    # update autoregistration
    def update_autoregistration(self, current_setting, tls_accept, tls_psk_identity, tls_psk):
        tls_accept_values = [
            None,
            'unsecure',
            'tls_with_psk'
        ]
        params = {}
        try:
            if isinstance(tls_accept, str):
                params['tls_accept'] = zabbix_utils.helper_to_numeric_value(
                    tls_accept_values, tls_accept
                )
            elif isinstance(tls_accept, list):
                params['tls_accept'] = 0
                for _tls_accept_value in tls_accept:
                    params['tls_accept'] += zabbix_utils.helper_to_numeric_value(
                        tls_accept_values, _tls_accept_value
                    )
            else:
                self._module.fail_json(msg="Value of tls_accept must be list or string.")

            if tls_psk_identity:
                params['tls_psk_identity'] = tls_psk_identity

            if tls_psk:
                params['tls_psk'] = tls_psk

            current_tls_accept = int(current_setting['tls_accept'])
            if (current_tls_accept == tls_accept_values.index('unsecure')
                    and params['tls_accept'] >= tls_accept_values.index('tls_with_psk')):
                if not tls_psk_identity or not tls_psk:
                    self._module.fail_json(msg="Please set tls_psk_identity and tls_psk.")

            if (not tls_psk_identity and not tls_psk
                    and params['tls_accept'] == current_tls_accept):
                self._module.exit_json(changed=False, result="Autoregistration is already up to date")

            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.autoregistration.update(params)
            self._module.exit_json(changed=True, result="Successfully updated global autoregistration setting")
        except Exception as e:
            self._module.fail_json(msg="Failed to update autoregistration: %s" % e)


def main():
    """Main ansible module function
    """

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        tls_accept=dict(
            type='list',
            elements='str',
            required=True
        ),
        tls_psk_identity=dict(type='str', required=False, no_log=True),
        tls_psk=dict(type='str', required=False, no_log=True),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password', 'timeout', 'validate_certs']:
        if p in module.params and not module.params[p] is None:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)

    tls_accept = module.params['tls_accept']
    tls_psk_identity = module.params['tls_psk_identity']
    tls_psk = module.params['tls_psk']

    autoregistration_class_obj = Autoregistration(module)
    current_setting = autoregistration_class_obj.get_autoregistration()
    autoregistration_class_obj.update_autoregistration(current_setting, tls_accept, tls_psk_identity, tls_psk)


if __name__ == '__main__':
    main()
