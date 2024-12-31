#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: zabbix_connector
short_description: Create/Delete/Update Zabbix connectors
description:
    - This module allows you to create, modify and delete Zabbix connectors.
author:
    - Loric Vandentempel (@loricvdt)
requirements:
    - "python >= 3.9"
version_added: 3.3.0
options:
    name:
        description:
            - Name of the connector.
        type: str
        required: true
    url:
        description:
            - URL of the receiver used by the connector.
        type: str
    data_type:
        description:
            - Type of data being streamed.
        type: str
        choices: ["item_values", "events"]
    item_value_types:
        description:
            - Parameter introduced in Zabbix 7.0
            - List of value types to stream.
            - Each element should be one of C(all), C(all+bin), C(numeric_float), C(character), C(log), C(numeric_unsigned), C(text) or C(binary).
            - C(all) represents all types except binary I((default)).
            - C(all+bin) represents all types, binary included.
        type: list
        elements: str
    max_records:
        description:
            - Maximum number of records sent in one message.
        type: int
    max_senders:
        description:
            - Number of sender processes used by the connector.
        type: int
    max_attempts:
        description:
            - Maximum number of attempts.
        type: int
    attempt_interval:
        description:
            - Parameter introduced in Zabbix 7.0
            - Interval between attempts in seconds (value between 0 and 10).
        type: int
    timeout:
        description:
            - Message sending timeout in seconds (value between 1 and 60).
        type: int
    http_proxy:
        description:
            - HTTP(S) proxy used by the connector.
        type: str
    auth_type:
        description:
            - HTTP authentication method used by the connector.
        type: str
        choices: ["none", "basic", "ntlm", "kerberos", "digest", "bearer"]
    username:
        description:
            - Username to authenticate the connector with the receiver.
            - Supported only if C(auth_type) is one of C(basic), C(ntlm), C(kerberos) or C(digest).
        type: str
    password:
        description:
            - Password to authenticate the connector with the receiver.
            - Supported only if C(auth_type) is one of C(basic), C(ntlm), C(kerberos) or C(digest).
        type: str
    token:
        description:
            - Bearer token to authenticate the connector with the receiver.
            - Required when C(auth_type=bearer).
        type: str
    verify_peer:
        description:
            - Whether the connector should verify the receiver's certificate.
        type: bool
    verify_host:
        description:
            - Whether the connector should verify the receiver's hostname against the certificate's CN or SAN fields.
        type: bool
    ssl_cert_file:
        description:
            - Public SSL key file path for client authentication.
        type: str
    ssl_key_file:
        description:
            - Private SSL key file path for client authentication.
        type: str
    ssl_key_password:
        description:
            - Password of the private SSL key file.
        type: str
    description:
        description:
            - Description of the connector.
        type: str
    enabled:
        description:
            - Whether the connector is enabled.
            - (mapped to the I(status) property of the connector object in the Zabbix API)
        type: bool
    tags_eval_type:
        description:
            - Tag filter evaluation method.
        type: str
        choices: ["and/or", "or"]
    tags:
        description:
            - List of tags to filter streamed data.
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Name of the tag.
                type: str
                required: true
            operator:
                description:
                    - Conditional operator used to filter .
                type: str
                choices: ["equals", "does not equal", "contains", "does not contain", "exists", "does not exist"]
            value:
                description:
                    - Value of the tag compared.
                type: str
    state:
        description:
            - State of the connector.
            - On C(present), it will create a connector if it does not exist or update the connector if the associated data is different.
            - On C(absent), it will remove the connector if it exists.
        type: str
        choices: ["present", "absent"]
        default: present

extends_documentation_fragment:
    - community.zabbix.zabbix
"""

EXAMPLES = r"""
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

- name: Create or update a connector
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    name: My app connector
    description: Connector to send item values to My app
    state: present
    enabled: true
    data_type: item_values
    url: https://my-app.example.com/api/zabbix-stream
    auth_type: bearer
    token: "{{ my_app_bearer_token }}"
    value_types:
      - numeric_float
      - character
      - numeric_unsigned
      - text
    tags_eval_type: and/or
    tags:
      - tag: to-my-app
        operator: exists
      - tag: privacy
        operator: does not equal
        value: hidden

- name: Delete a connector
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    name: My app connector
    state: absent
"""

RETURN = r"""
msg:
    description: Text result of the operation.
    returned: always
    type: str
    sample: "Successfully updated connector 'My app connector' (id: 2)"
result:
    description: JSON result of the Zabbix API call
    returned: success
    type: dict
    sample: '{"connectorids": ["2"]}'
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Connector(ZabbixBase):

    existing_data = None

    DATA_TYPES = {
        "item_values": "0",
        "events": "1",
    }

    VALUE_TYPES = {
        "numeric_float": 1,
        "character": 2,
        "log": 4,
        "numeric_unsigned": 8,
        "text": 10,
        "binary": 20,
    }

    AUTH_TYPES = {
        "none": "0",
        "basic": "1",
        "ntlm": "2",
        "kerberos": "3",
        "digest": "4",
        "bearer": "5",
    }

    EVAL_TYPES = {
        "and/or": "0",
        "or": "2",
    }

    OPERATORS = {
        "equals": "0",
        "does not equal": "1",
        "contains": "2",
        "does not contain": "3",
        "exists": "12",
        "does not exist": "1",
    }

    def get_connector(self, name):
        """
        Gets the connector for the given name and returns its id, or None if it doesn't exist
        :param name: name of the connector
        :return: connector ID
        """
        try:
            result = self._zapi.connector.get({
                "filter": {"name": name},
                "output": "extend",
                "selectTags": ["tag", "operator", "value"]
            })
            if len(result) > 0 and "connectorid" in result[0]:
                self.existing_data = result[0]
                return result[0]["connectorid"]
            else:
                return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get connector '%s': %s" % (name, e))

    def add_connector(self, params):
        """
        Creates the connector with the given parameters
        :param params: parameter dictionary (see Zabbix API)
        """
        try:
            result = self._zapi.connector.create(params)
            self._module.exit_json(changed=True, msg="Successfully created connector '%s'" % params["name"], result=result)
        except Exception as e:
            self._module.fail_json(msg="Failed to create connector '%s': %s" % (params["name"], e))

    def update_connector(self, connector_id, params):
        """
        Updates the connector with the given ID with the provided updated parameters, only if they lead to changes
        :param connector_id: ID of the connector to update
        :param params: updated parameters
        """
        diff = {
            k: v for k, v in params.items() if self.existing_data.get(k) != v
        }
        if diff == {}:
            self._module.exit_json(
                changed=False, msg="Connector '%s' (id: %s) already up to date" % (params["name"], connector_id), result={"connectorids": [str(connector_id)]})
        else:
            try:
                diff["connectorid"] = connector_id
                result = self._zapi.connector.update(diff)
                self._module.exit_json(
                    changed=True, msg="Successfully updated connector '%s' (id: %s)" % (params["name"], connector_id), result=result)
            except Exception as e:
                self._module.fail_json(msg="Failed to update connector '%s': %s" % (params["name"], e))

    def delete_connector(self, connector_id, name):
        """
        Deletes the connector with the given ID
        :param connector_id: ID of the connector to delete
        :param name: name opf the connector (only used for verbosity)
        """
        try:
            result = self._zapi.connector.delete([connector_id])
            self._module.exit_json(changed=True, msg="Successfully deleted connector '%s' (id: %s)" % (name, connector_id), result=result)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete connector '%s': %s" % (name, e))

    def sanitize_params(self, params):
        """
        Transforms the module parameters to their corresponding Zabbix API values
        :param params: module parameters
        :return: Zabbix API compatible parameters
        """
        sanitized = {
            "name": params["name"],
            "url": params["url"],
            "data_type": Connector.DATA_TYPES.get(params["data_type"]),
            "max_records": str(params["max_records"]) if params["max_records"] is not None else None,
            "max_senders": str(params["max_senders"]) if params["max_senders"] is not None else None,
            "max_attempts": str(params["max_attempts"]) if params["max_attempts"] is not None else None,
            "attempt_interval": str(params["attempt_interval"]) if params["attempt_interval"] is not None else None,
            "timeout": str(params["timeout"]) if params["timeout"] is not None else None,
            "http_proxy": params["http_proxy"],
            "authtype": Connector.AUTH_TYPES.get(params["auth_type"]),
            "username": params["username"],
            "password": params["password"],
            "token": params["token"],
            "verify_peer": str(int(params["verify_peer"])) if params["verify_peer"] is not None else None,
            "verify_host": str(int(params["verify_host"])) if params["verify_host"] is not None else None,
            "ssl_cert_file": params["ssl_cert_file"],
            "ssl_key_file": params["ssl_key_file"],
            "ssl_key_password": params["ssl_key_password"],
            "description": params["description"],
            "status": str(int(params["enabled"])) if params["enabled"] is not None else None,
            "tags_evaltype": Connector.EVAL_TYPES.get(params["tags_eval_type"]),
        }

        if params["item_value_types"] is not None:
            value_types = set(params["item_value_types"])
            if "all" in value_types:
                sanitized["item_value_type"] = "31"
            elif "all+bin" in value_types:
                sanitized["item_value_type"] = "51"  # 31 + 20
            else:
                sum_value = 0
                for value_type in value_types:
                    value = Connector.VALUE_TYPES.get(value_type)
                    if value is None:
                        self._module.fail_json(msg="'%s' is not a known value type, should be one of %s" %
                                                   (value_type, Connector.VALUE_TYPES.keys()))
                    sum_value += value
                sanitized["item_value_type"] = str(sum_value)

        if params["tags"] is not None:
            tags = []
            for tag_def in params["tags"]:
                tag = {
                    "tag": tag_def["tag"],
                    "operator": Connector.OPERATORS.get(tag_def["operator"], 0),
                    "value": tag_def.get("value") or ""
                }
                tags.append(tag)
            sanitized["tags"] = tags

        return zabbix_utils.helper_cleanup_data(sanitized)


def main():
    """
    Main module entry point
    """
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        url=dict(type="str"),
        data_type=dict(type="str", choices=list(Connector.DATA_TYPES.keys())),
        item_value_types=dict(type="list", elements="str"),
        max_records=dict(type="int"),
        max_senders=dict(type="int"),
        max_attempts=dict(type="int"),
        attempt_interval=dict(type="int"),
        timeout=dict(type="int"),
        http_proxy=dict(type="str"),
        auth_type=dict(type="str", choices=list(Connector.AUTH_TYPES.keys())),
        username=dict(type="str"),
        password=dict(type="str", no_log=True),
        token=dict(type="str", no_log=True),
        verify_peer=dict(type="bool"),
        verify_host=dict(type="bool"),
        ssl_cert_file=dict(type="str"),
        ssl_key_file=dict(type="str"),
        ssl_key_password=dict(type="str", no_log=True),
        description=dict(type="str"),
        enabled=dict(type="bool"),  # "status" in API
        tags_eval_type=dict(type="str", choices=list(Connector.EVAL_TYPES.keys())),
        tags=dict(
            type="list",
            elements="dict",
            options=dict(
                tag=dict(type="str", required=True),
                operator=dict(type="str", choices=list(Connector.OPERATORS.keys())),
                value=dict(type="str")
            )
        ),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ["username", "token"],
            ["password", "token"],
        ],
        required_if=[
            ["state", "present", ["data_type", "url"]],
            ["auth_type", "basic", ["username", "password"]],
            ["auth_type", "ntlm", ["username", "password"]],
            ["auth_type", "kerberos", ["username", "password"]],
            ["auth_type", "digest", ["username", "password"]],
            ["auth_type", "bearer", ["token"]],
        ],
    )

    name = module.params["name"]
    state = module.params["state"]

    connector = Connector(module)
    connector_id = connector.get_connector(name)

    if state == "absent":
        if connector_id:
            connector.delete_connector(connector_id, name)
        else:
            module.exit_json(changed=False, msg="Connector '%s' already absent" % name)
    elif state == "present":
        params = connector.sanitize_params(module.params)

        if connector_id:
            connector.update_connector(connector_id, params)
        else:
            connector.add_connector(params)


if __name__ == "__main__":
    main()
