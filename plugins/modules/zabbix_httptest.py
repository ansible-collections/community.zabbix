#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_httptest
short_description: Create/delete Zabbix httptests aka Web Scenarios
description:
   - Create httptests if they do not exist.
   - Delete existing httptests if they exist.
author:
    - "Trystan Mata (@tytan652)"
requirements:
    - "python >= 3.9"

options:
    state:
        description:
            - Create or delete httptest.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of httptest to create or delete.
        required: true
        type: str
    host_name:
        description:
            - Name of host to add httptest to.
        required: true
        type: str
    params:
        description:
            - Parameters to create/update httptest with.
            - Required if state is "present".
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/httptest/object
            - Additionally supported parameters are below.
        required: false
        type: dict
        suboptions:
            interval:
                description:
                    - Update interval of the httptest.
                    - Alias for "delay" in API docs.
                required: false
                type: str
            attempts:
                description:
                    - Number of attempts before failing the httptest
                    - Alias for "retries" in API docs
                required: false
                type: int
            agent:
                description:
                    - User agent string used by the httptest.
                required: false
                type: str
            http_proxy:
                description:
                    - HTTP(S) proxy used by the httptest
                required: false
                type: str
            variables:
                description:
                    - httptest variables.
                    - Overriden by I(steps) variables.
                required: false
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of the variable field.
                        required: true
                        type: str
                    value:
                        description:
                            - Value of the variable field.
                        required: true
                        type: str
            headers:
                description:
                    - HTTP headers used when performing the httptest.
                    - Overriden by I(steps) headers.
                required: false
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of the header field.
                        required: true
                        type: str
                    value:
                        description:
                            - Value of the header field.
                        required: true
                        type: str
            status:
                description:
                    - Status of the httptest.
                required: false
                type: str
                choices: [ "enabled", "disabled" ]
            enabled:
                description:
                    - Status of the httptest.
                    - Overrides "status" in API docs.
                required: false
                type: bool
            new_name:
                description:
                    - New name for httptest
                required: false
                type: str
            steps:
                description:
                    - Scenario steps for the httptest
                    - Required if state is "present" and creating an httptest.
                required: false
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of the scenario step.
                        required: true
                        type: str
                    url:
                        description:
                            - URL to be checked.
                        required: true
                        type: str
                    query_field:
                        description:
                            - Query fields used when performing the scenario step.
                        required: false
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name of the query field.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value of the query field.
                                required: true
                                type: str
                    posts:
                        description:
                            - POST variables for the scenario step.
                        required: false
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name of the POST field.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value of the POST field.
                                required: true
                                type: str
                    variables:
                        description:
                            - Variables used when performing the scenario step.
                            - Overrides I(params) variables.
                        required: false
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name of the variable field.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value of the variable field.
                                required: true
                                type: str
                    headers:
                        description:
                            - HTTP headers used when performing the scenario step.
                            - Overrides I(params) headers.
                        required: false
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name of the header field.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value of the header field.
                                required: true
                                type: str
                    follow_redirects:
                        description:
                            - Whether to follow HTTP redirects.
                        required: false
                        type: bool
                    retrieve_mode:
                        description:
                            - Part of the HTTP response that the scenario step must retrieve.
                        required: false
                        type: str
                        choices: ["only_body", "only_headers", "headers_and_body"]
                    timeout:
                        description:
                            - Request timeout of the scenario step.
                        required: false
                        type: str
                    required:
                        description:
                            - Text that must be present in the response.
                        required: false
                        type: str
                    status_codes:
                        description:
                            - Expected response status code.
                        required: false
                        type: list
                        elements: int
            tags:
                description:
                    - Tags of the httptest.
                required: false
                type: list
                elements: dict
                suboptions:
                    tag:
                        description:
                            - Name of the httptest tag.
                        required: true
                        type: str
                    value:
                        description:
                            - Value of the httptest tag.
                        required: false
                        type: str
            authentication:
                description:
                    - HTTP authentication method used by the httptest.
                required: false
                type: str
                choices: ["none", "basic", "ntlm"]
            username:
                description:
                    - Username to authenticate with the host.
                    - Used if C(authentication) is one of C(basic) or C(ntlm)
                    - Alias for "http_user" in API docs.
                required: false
                type: str
            password:
                description:
                    - Password to authenticate with the host.
                    - Used if C(authentication) is one of C(basic) or C(ntlm)
                    - Alias for "http_password" in API docs.
                required: false
                type: str
            verify_peer:
                description:
                    - Whether the httptest should verify the host's certificate.
                required: false
                type: bool
            verify_host:
                description:
                    - Whether the httptest should verify the host's hostname.
                required: false
                type: bool
            ssl_cert_file:
                description:
                    - Public SSL key file path for client authentication.
                required: false
                type: str
            ssl_key_file:
                description:
                    - Private SSL key file path for client authentication.
                required: false
                type: str
            ssl_key_password:
                description:
                    - Password of the private SSL key file.
                required: false
                type: str

extends_documentation_fragment:
- community.zabbix.zabbix
'''

EXAMPLES = r'''

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

# Create a web scenario on example_host
- name: create httptest
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_httptest:
    name: example_host_website
    host_name: example_host
    params:
      steps:
        - name: Test
          url: https://zabbix-example-fqdn.org
          status_code: [200]
      interval: 1h
      enabled: True
    state: present

# Change interval for existing Zabbix web scenario
- name: update rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: example_host_website
    host_name: example_host
    params:
      interval: 2h
    state: present

# Delete web scenario
- name: delete rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: example_host_website
    host_name: example_host
    state: absent

- name: Rename Zabbix web scenario
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: example_host_website
    host_name: example_host
    params:
      new_name: new_example_host_website
    state: present
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Httptest(ZabbixBase):
    RETRIEVE_MODES = {'only_body': 0,
                      'only_headers': 1,
                      'headers_and_body': 2}

    AUTHENTICATION_TYPES = {'none': 0,
                            'basic': 1,
                            'ntlm': 2}

    def get_hosts(self, host_name):
        try:
            return self._zapi.host.get({"filter": {"host": host_name}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get host: %s" % e)

    def get_httptests(self, httptest_name, host_name):
        httptests = []
        try:
            httptests = self._zapi.httptest.get({'filter': {'name': httptest_name, 'host': host_name}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get httptests: %s" & e)
        return httptests

    def sanitize_params(self, name, params):
        params['name'] = name
        if 'interval' in params:
            params['delay'] = params['interval']
            params.pop("interval")
        if 'attempts' in params:
            params['retries'] = params['attempts']
            params.pop("attempts")
        if 'enabled' in params:
            if params['enabled']:
                params['status'] = 'enabled'
            else:
                params['status'] = 'disabled'
            params.pop("enabled")
        if 'status' in params:
            status = params['status']
            if status == 'enabled':
                params['status'] = 0
            elif status == 'disabled':
                params['status'] = 1
            else:
                self._module.fail_json(msg="Status must be 'enabled' or 'disabled', got %s" % status)
        if 'steps' in params:
            no = 0
            for step in params['steps']:
                no += 1
                step['no'] = no
                if 'follow_redirects' in step:
                    follow_redirects = step['follow_redirects']
                    if follow_redirects:
                        step['follow_redirects'] = 1
                    else:
                        step['follow_redirects'] = 0
                if 'retrieve_mode' in step:
                    retrieve_mode_int = self.RETRIEVE_MODES[step['retrieve_mode']]
                    step['retrieve_mode'] = retrieve_mode_int
                if 'status_codes' in step:
                    status_codes_str = ",".join(str(code) for code in step['status_codes'])
                    step['status_codes'] = status_codes_str
        if 'authentication' in params:
            authentication_int = self.AUTHENTICATION_TYPES[params['authentication']]
            params['authentication'] = authentication_int
        if 'username' in params:
            params['http_user'] = params['username']
            params.pop("username")
        if 'password' in params:
            params['http_password'] = params['password']
            params.pop("password")
        if 'verify_peer' in params:
            verify = params['verify_peer']
            if verify:
                params['verify_peer'] = 1
            else:
                params['verify_peer'] = 0
        if 'verify_host' in params:
            verify = params['verify_host']
            if verify:
                params['verify_host'] = 1
            else:
                params['verify_host'] = 0

    def add_httptest(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.httptest.create(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to create httptest: %s" % e)
        return results

    def update_httptest(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.httptest.update(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update httptest: %s" % e)
        return results

    def check_httptest_changed(self, old_httptest):
        try:
            new_httptest = self._zapi.httptest.get({'httptestids': "%s" % old_httptest['httptestid']})[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get httptest: %s" % e)
        return old_httptest != new_httptest

    def delete_httptests(self, httptest_ids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.httptest.delete(httptest_ids)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete httptests: %s" % e)
        return results


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        host_name=dict(type='str', required=True),
        params=dict(type='dict', required=False),
        state=dict(type='str', default="present", choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ['state', 'present', ['params']]
        ],
        supports_check_mode=True
    )

    name = module.params['name']
    host_name = module.params['host_name']
    params = module.params['params']
    state = module.params['state']

    httptest = Httptest(module)

    if state == "absent":
        httptests = httptest.get_httptests(name, host_name)
        if len(httptests) == 0:
            module.exit_json(changed=False, result="No httptest to delete.")
        else:
            delete_ids = []
            for h in httptests:
                delete_ids.append(h['httptestid'])
            results = httptest.delete_httptests(delete_ids)
            module.exit_json(changed=True, result=results)

    elif state == "present":
        httptest.sanitize_params(name, params)
        httptests = httptest.get_httptests(name, host_name)
        if 'new_name' in params:
            new_name_httptest = httptest.get_httptests(params['new_name'], host_name)
            if len(new_name_httptest) > 0:
                module.exit_json(changed=False, results=[{'httptestids': [new_name_httptest[0]['httptestid']]}])
        results = []
        if len(httptests) == 0:
            if 'new_name' in params:
                module.fail_json('Cannot rename httptest: %s is not found' % name)
            if not ('steps' in params):
                module.fail_json('Cannot create httptest without steps')
            hosts = httptest.get_hosts(host_name)
            for host in hosts:
                if 'hostid' in host:
                    params['hostid'] = host['hostid']
                else:
                    module.fail_json(msg="host did not return id")
                results.append(httptest.add_httptest(params))
            module.exit_json(changed=True, result=results)
        else:
            changed = False
            for h in httptests:
                params['httptestid'] = h['httptestid']
                if 'new_name' in params:
                    params['name'] = params['new_name']
                    params.pop("new_name")
                results.append(httptest.update_httptest(params))
                changed_test = httptest.check_httptest_changed(h)
                if changed_test:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
