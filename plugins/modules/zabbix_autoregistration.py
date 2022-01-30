#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_autoregistration

short_description: Update Zabbix autoregistration


description:
    - This module allows you to modify Zabbix autoregistration.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "zabbix-api >= 0.5.4"

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
            - TLS connection use this PSK identity string.
            - The PSK identity string will be transmitted unencrypted over the network. Therefore, you should not put sensitive information.
            - It is required if you set C(tls_with_psk) to I(tls_accept) and current tls_accept is C(unsecure).
        type: str
    tls_psk:
        description:
            - TLS connection use this PSK value.
            - It is required if you set C(tls_with_psk) to I(tls_accept) and current tls_accept is C(unsecure).
        type: str

notes:
    - Only Zabbix >= 4.4 is supported.
    - This module returns state of changed is true when you set values to I(tls_psk_identity) and I(tls_psk).

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = '''
- name: Update autoregistration
  community.zabbix.zabbix_autoregistration:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
    tls_accept:
      - unsecure
      - tls_with_psk
    tls_psk_identity: 'PSK 001'
    tls_psk: "11111595725ac58dd977beef14b97461a7c1045b9a1c923453302c5473193478"

- name: Set unsecure to tls_accept
  community.zabbix.zabbix_autoregistration:
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
    sample: 'Successfully update autoregistration'
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Autoregistration(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(Autoregistration, self).__init__(module, zbx, zapi_wrapper)
        self.existing_data = None
        if LooseVersion(self._zbx_api_version) < LooseVersion('4.4.0'):
            module.fail_json(msg="This module unsuport Zabbix %s" % self._zbx_api_version)

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
            self._module.exit_json(changed=True, result="Successfully update autoregistration")
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
        tls_psk_identity=dict(type='str', required=False),
        tls_psk=dict(type='str', required=False),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    tls_accept = module.params['tls_accept']
    tls_psk_identity = module.params['tls_psk_identity']
    tls_psk = module.params['tls_psk']

    autoregistration_class_obj = Autoregistration(module)
    current_setting = autoregistration_class_obj.get_autoregistration()
    autoregistration_class_obj.update_autoregistration(current_setting, tls_accept, tls_psk_identity, tls_psk)


if __name__ == '__main__':
    main()
