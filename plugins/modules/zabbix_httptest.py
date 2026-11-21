#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_httptest
short_description: Manage Zabbix httptests aka Web Scenarios
description:
   - Create or update httptests on hosts or templates.
   - Delete existing httptests if they exist.
author:
    - "Trystan Mata (@tytan652)"
requirements:
    - "python >= 3.9"

options:
    state:
        description:
            - Create, update, or delete httptest.
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
            - Required when I(template_name) is not used.
            - Mutually exclusive with I(template_name).
        required: false
        type: str
    template_name:
        description:
            - Technical name of the template to add httptest to.
            - Required if I(host_name) is not used.
            - Mutually exclusive with I(host_name).
        required: false
        type: str
    params:
        description:
            - Parameters to create/update httptest with.
            - Required if state is "present".
            - Supported writable parameters from https://www.zabbix.com/documentation/current/en/manual/api/reference/httptest/object.
            - Suboptions use native API field names. Previous module names remain supported as compatibility aliases.
            - Only supplied parameters are compared and updated. IDs and inherited properties are managed by Zabbix or the module.
        required: false
        type: dict
        suboptions:
            delay:
                description:
                    - Update interval of the httptest.
                required: false
                type: str
                aliases: [interval]
            retries:
                description:
                    - Number of attempts before failing the httptest
                required: false
                type: int
                aliases: [attempts]
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
                choices: [enabled, disabled]
            enabled:
                description:
                    - Compatibility option that overrides I(params.status). Use I(params.status) for the native API option.
                    - C(true) enables the scenario (status C(0)); C(false) disables it (status C(1)).
                required: false
                type: bool
            name:
                description:
                    - New name for the httptest identified by the top-level I(name).
                    - For Zabbix 7.0 and later, include I(params.steps) when renaming a scenario on a template linked to hosts to avoid an API error.
                required: false
                type: str
                aliases: [new_name]
            steps:
                description:
                    - Scenario steps for the httptest
                    - Required if state is "present" and creating an httptest.
                    - Steps without an explicit I(params.steps.no) are numbered by their position in the list.
                    - When updating, this list replaces all existing steps. Include every step to retain; omitted steps are deleted.
                required: false
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of the scenario step.
                            - Required when I(params.steps.httpstepid) is not supplied.
                        required: false
                        type: str
                    url:
                        description:
                            - URL to be checked.
                            - Required when I(params.steps.httpstepid) is not supplied.
                        required: false
                        type: str
                    httpstepid:
                        description:
                            - ID of an existing step to update. Allows omitting fields such as I(params.steps.name) and I(params.steps.url).
                            - The I(params.steps) list still replaces all existing steps; include every step to retain.
                        type: str
                    'no':
                        description:
                            - Positive sequence number of the step. Defaults to its position in the list.
                        type: int
                    query_fields:
                        description:
                            - Query fields used when performing the scenario step.
                        required: false
                        type: list
                        elements: dict
                        aliases: [query_field]
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
                            - Raw POST data as a string, or form fields as a list of dictionaries containing C(name) and C(value).
                        required: false
                        type: raw
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
                        choices: [only_body, only_headers, headers_and_body]
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
                            - List of expected HTTP status codes or ranges, for example C(["200", "300-399"]).
                            - An empty list disables the status-code check.
                        required: false
                        type: list
                        elements: str
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
                        default: ""
            authentication:
                description:
                    - HTTP authentication method used by the httptest.
                    - Kerberos and Digest require Zabbix 7.0 or later and are rejected on older servers.
                required: false
                type: str
                choices: [none, basic, ntlm, kerberos, digest]
            http_user:
                description:
                    - Username to authenticate with the host.
                    - Used when HTTP authentication is enabled.
                required: false
                type: str
                aliases: [username]
            http_password:
                description:
                    - Password to authenticate with the host.
                    - Used when HTTP authentication is enabled.
                required: false
                type: str
                aliases: [password]
            uuid:
                description:
                    - UUID of a web scenario on a template. Generated by Zabbix when omitted during creation.
                    - Only supported with I(template_name).
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
          status_codes: ["200"]
      delay: 1h
      status: enabled
    state: present

# Create a web scenario on a template
- name: Create httptest on a template
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_httptest:
    name: example_template_website
    template_name: example_template
    params:
      steps:
        - name: Test
          url: https://example.com
          status_codes: ["200"]
      delay: 1h
      status: enabled
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
  community.zabbix.zabbix_httptest:
    name: example_host_website
    host_name: example_host
    params:
      delay: 2h
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
  community.zabbix.zabbix_httptest:
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
  community.zabbix.zabbix_httptest:
    name: example_host_website
    host_name: example_host
    params:
      name: new_example_host_website
    state: present
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.compat.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def httptest_argument_spec():
    http_fields = dict(type='list', elements='dict', options=dict(
        name=dict(type='str', required=True),
        value=dict(type='str', required=True),
    ))
    return dict(
        delay=dict(type='str', aliases=['interval']),
        retries=dict(type='int', aliases=['attempts']),
        agent=dict(type='str'),
        http_proxy=dict(type='str'),
        variables=http_fields,
        headers=http_fields,
        status=dict(type='str', choices=['enabled', 'disabled']),
        enabled=dict(type='bool'),
        name=dict(type='str', aliases=['new_name']),
        authentication=dict(type='str', choices=['none', 'basic', 'ntlm', 'kerberos', 'digest']),
        http_user=dict(type='str', aliases=['username']),
        http_password=dict(type='str', aliases=['password'], no_log=True),
        uuid=dict(type='str'),
        verify_peer=dict(type='bool'),
        verify_host=dict(type='bool'),
        ssl_cert_file=dict(type='str'),
        ssl_key_file=dict(type='str'),
        ssl_key_password=dict(type='str', no_log=True),
        tags=dict(type='list', elements='dict', options=dict(
            tag=dict(type='str', required=True),
            value=dict(type='str', default=''),
        )),
        steps=dict(type='list', elements='dict', options=dict(
            name=dict(type='str'),
            url=dict(type='str'),
            httpstepid=dict(type='str'),
            no=dict(type='int'),
            query_fields=dict(http_fields, aliases=['query_field']),
            posts=dict(type='raw'),
            variables=http_fields,
            headers=http_fields,
            follow_redirects=dict(type='bool'),
            retrieve_mode=dict(type='str', choices=['only_body', 'only_headers', 'headers_and_body']),
            timeout=dict(type='str'),
            required=dict(type='str'),
            status_codes=dict(type='list', elements='str'),
        )),
    )


class Httptest(ZabbixBase):
    RETRIEVE_MODES = {'only_body': 0,
                      'only_headers': 1,
                      'headers_and_body': 2}

    AUTHENTICATION_TYPES = {'none': 0,
                            'basic': 1,
                            'ntlm': 2,
                            'kerberos': 3,
                            'digest': 4}

    HTTPTEST_PARAMETERS = (
        'name', 'agent', 'authentication', 'delay', 'headers', 'http_password',
        'http_proxy', 'http_user', 'retries', 'ssl_cert_file', 'ssl_key_file',
        'ssl_key_password', 'status', 'variables', 'verify_host', 'verify_peer',
        'uuid', 'steps', 'tags',
    )

    def get_hosts_templates(self, host_name, template_name):
        if host_name is not None:
            try:
                return self._zapi.host.get({"filter": {"host": host_name}})
            except Exception as e:
                self._module.fail_json(msg="Failed to get host: %s" % e)
        else:
            try:
                return self._zapi.template.get({"filter": {"host": template_name}})
            except Exception as e:
                self._module.fail_json(msg="Failed to get template: %s" % e)

    def get_httptests(self, httptest_name, host_name, template_name):
        hosts_templates = self.get_hosts_templates(host_name, template_name)
        if not hosts_templates:
            return []
        query = {'filter': {'name': httptest_name}, 'selectSteps': 'extend', 'selectTags': 'extend'}
        if host_name is not None:
            query['hostids'] = [host['hostid'] for host in hosts_templates]
        else:
            query['templateids'] = [template['templateid'] for template in hosts_templates]
        httptests = []
        try:
            httptests = self._zapi.httptest.get(query)
        except Exception as e:
            self._module.fail_json(msg="Failed to get httptests: %s" % e)
        return httptests

    def sanitize_params(self, name, params):
        # Argument validation adds None for unspecified options. Keep raw lists intact
        # so invalid entries are rejected rather than silently removed.
        for key in list(params):
            if params[key] is None:
                del params[key]
        # Ansible resolves aliases but also retains their original keys.
        for alias in ('interval', 'attempts', 'username', 'password', 'new_name'):
            params.pop(alias, None)
        params.setdefault('name', name)
        if 'enabled' in params:
            if params['enabled']:
                params['status'] = 'enabled'
            else:
                params['status'] = 'disabled'
            params.pop("enabled")
        if 'status' in params:
            params['status'] = {'enabled': 0, 'disabled': 1}[params['status']]
        if 'steps' in params:
            if not params['steps']:
                self._module.fail_json(msg="steps must contain at least one scenario step")
            step_numbers = set()
            for no, step in enumerate(params['steps'], 1):
                for key in list(step):
                    if step[key] is None:
                        del step[key]
                if 'httpstepid' not in step and ('name' not in step or 'url' not in step):
                    self._module.fail_json(msg="Each step requires name and url unless httpstepid is supplied")
                step.setdefault('no', no)
                if step['no'] < 1 or step['no'] in step_numbers:
                    self._module.fail_json(msg="Step sequence numbers must be positive and unique")
                step_numbers.add(step['no'])
                if 'query_field' in step:
                    step['query_fields'] = step.pop('query_field')
                if 'follow_redirects' in step:
                    step['follow_redirects'] = int(step['follow_redirects'])
                if 'retrieve_mode' in step:
                    step['retrieve_mode'] = self.RETRIEVE_MODES[step['retrieve_mode']]
                if 'status_codes' in step:
                    step['status_codes'] = ",".join(step['status_codes'])
                if 'posts' in step and not isinstance(step['posts'], str):
                    posts = step['posts']
                    if not isinstance(posts, list) or any(
                        not isinstance(field, dict) or set(field) != {'name', 'value'}
                        or not isinstance(field['name'], str) or not isinstance(field['value'], str)
                        for field in posts
                    ):
                        self._module.fail_json(msg="posts must be a string or a list of dictionaries with string name and value fields")
        if 'authentication' in params:
            params['authentication'] = self.AUTHENTICATION_TYPES[params['authentication']]
            if params['authentication'] in (3, 4) and LooseVersion(self._zbx_api_version) < LooseVersion('7.0'):
                self._module.fail_json(msg="Kerberos and Digest authentication require Zabbix 7.0 or later")
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

    def params_equal(self, desired, current, key=None):
        # Compare supplied fields only: API responses add defaults/IDs and stringify numbers.
        if key == 'steps':
            desired = sorted(desired, key=lambda step: int(step['no']))
            current = sorted(current, key=lambda step: int(step['no']))
        elif key == 'tags':
            desired = sorted(desired, key=lambda tag: (tag['tag'], tag.get('value', '')))
            current = sorted(current, key=lambda tag: (tag['tag'], tag.get('value', '')))
        elif key == 'variables':
            desired = sorted(desired, key=lambda variable: variable['name'])
            current = sorted(current, key=lambda variable: variable['name'])
        if isinstance(desired, dict):
            return isinstance(current, dict) and all(
                field in current and self.params_equal(value, current[field], field)
                for field, value in desired.items()
            )
        if isinstance(desired, list):
            return isinstance(current, list) and len(desired) == len(current) and all(
                self.params_equal(value, old) for value, old in zip(desired, current)
            )
        return str(desired) == str(current)

    def add_httptest(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            payload = {key: params[key] for key in self.HTTPTEST_PARAMETERS if key in params}
            payload['hostid'] = params['hostid']
            results = self._zapi.httptest.create(payload)
        except Exception as e:
            self._module.fail_json(msg="Failed to create httptest: %s" % e)
        return results

    def update_httptest(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            payload = {key: params[key] for key in self.HTTPTEST_PARAMETERS if key in params}
            payload['httptestid'] = params['httptestid']
            results = self._zapi.httptest.update(payload)
        except Exception as e:
            self._module.fail_json(msg="Failed to update httptest: %s" % e)
        return results

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
        host_name=dict(type='str', required=False),
        template_name=dict(type='str', required=False),
        params=dict(type='dict', required=False, options=httptest_argument_spec()),
        state=dict(type='str', default="present", choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[
            ['host_name', 'template_name']
        ],
        mutually_exclusive=[
            ['host_name', 'template_name']
        ],
        required_if=[
            ['state', 'present', ['params']]
        ],
        supports_check_mode=True
    )

    name = module.params['name']
    host_name = module.params['host_name']
    template_name = module.params['template_name']
    params = module.params['params']
    state = module.params['state']

    httptest = Httptest(module)

    if state == "absent":
        httptests = httptest.get_httptests(name, host_name, template_name)
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
        if 'uuid' in params and template_name is None:
            module.fail_json(msg="uuid is only supported for web scenarios on templates; use template_name")
        httptests = httptest.get_httptests(name, host_name, template_name)
        rename = params['name'] != name
        if rename:
            new_name_httptest = httptest.get_httptests(params['name'], host_name, template_name)
            if len(new_name_httptest) > 0:
                module.exit_json(changed=False, results=[{'httptestids': [new_name_httptest[0]['httptestid']]}])
        results = []
        if len(httptests) == 0:
            if rename:
                module.fail_json('Cannot rename httptest: %s is not found' % name)
            if not ('steps' in params):
                module.fail_json('Cannot create httptest without steps')
            hosts_templates = httptest.get_hosts_templates(host_name, template_name)
            if not hosts_templates:
                module.fail_json(msg="Host/template not found: %s" % (host_name if host_name is not None else template_name))
            for host_template in hosts_templates:
                if 'hostid' in host_template:
                    params['hostid'] = host_template['hostid']
                elif 'templateid' in host_template:
                    params['hostid'] = host_template['templateid']
                else:
                    module.fail_json(msg="host/template did not return id")
                results.append(httptest.add_httptest(params))
            module.exit_json(changed=True, result=results)
        else:
            changed = False
            for h in httptests:
                params['httptestid'] = h['httptestid']
                if not httptest.params_equal(params, h):
                    results.append(httptest.update_httptest(params))
                    changed = True
                else:
                    results.append({'httptestids': [h['httptestid']]})
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
