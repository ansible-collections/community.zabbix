#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# TODO
DOCUMENTATION = r"""
"""

EXAMPLES = r"""
"""

RETURN = r"""
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
        "numeric_float": "1",
        "character": "2",
        "log": "4",
        "numeric_unsigned": "8",
        "text": "10",
        "binary": "20",
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
        try:
            result = self._zapi.connector.get({"filter": {"name": name}})
            if len(result) > 0 and "connectorid" in result[0]:
                self.existing_data = result[0]
                return result[0]["connectorid"]
            else:
                return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get connector %s: %s" % (name, e))

    def add_connector(self, params):
        try:
            result = self._zapi.connector.create(params)
            self._module.exit_json(changed=True, result=result)
        except Exception as e:
            self._module.fail_json(msg="Failed to create connector: %s" % e)

    def update_connector(self, connector_id, params):
        diff = {
            k: v for k, v in params.items() if self.existing_data.get(k) != v
        }
        if diff == {}:
            self._module.exit_json(changed=False)
        else:
            try:
                diff["connectorid"] = connector_id
                result = self._zapi.connector.update(diff)
                self._module.exit_json(
                    changed=True,
                    # TODO: better handle API results
                    result="Successfully updated connector %s (%s)" %
                           (params["name"], connector_id)
                )
            except Exception as e:
                self._module.fail_json(msg="Failed to update connector %s: %s" %
                                           (params["name"], e))



    def delete_connector(self, connector_id, name):
        try:
            self._zapi.connector.delete([connector_id])
            self._module.exit_json(changed=True, result="Successfully deleted connector %s" % name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete connector %s: %s" % (name, str(e)))

    def sanitize_params(self, params):
        sanitized = {
            "name": params["name"],
            "url": params["url"],
            "data_type": Connector.DATA_TYPES.get(params["data_type"]),
            "max_records": str(params["max_records"]),
            "max_senders": str(params["max_senders"]),
            "max_attempts": str(params["max_attempts"]),
            "attempt_interval": params["attempt_interval"],
            "timeout": params["timeout"],
            "http_proxy": params["http_proxy"],
            "auth_type": Connector.AUTH_TYPES.get(params["auth_type"]),
            "username": params["username"],
            "password": params["password"],
            "token": params["token"],
            "ssl_cert_file": params["ssl_cert_file"],
            "ssl_key_file": params["ssl_key_file"],
            "ssl_key_password": params["ssl_key_password"],
            "description": params["description"],
            "tags_eval_type": Connector.EVAL_TYPES.get(params["tags_eval_type"]),
        }

        if params["item_value_types"] is not None:
            value_types = params["item_value_types"]
            if "all" in value_types:
                sanitized["item_value_type"] = "31"
            elif "all+bin" in value_types:
                sanitized["item_value_type"] = "51" # 31 + 20
            else:
                sum_value = 0
                for value_type in value_types:
                    value = Connector.VALUE_TYPES.get(value_type)
                    if value is None:
                        self._module.fail_json(msg="'%s' is not a known value type, should be one of %s" %
                                                   (value_type, Connector.VALUE_TYPES.keys()))
                    sum_value += value
                sanitized["item_value_type"] = str(sum_value)

        if params["verify_peer"] is not None:
            sanitized["verify_peer"] = str(int(params["verify_peer"])) # bool to '1' or '0'
        if params["verify_host"] is not None:
            sanitized["verify_host"] = str(int(params["verify_host"]))
        if params["enabled"] is not None:
            sanitized["status"] = str(int(params["enabled"]))
        if params["tags"] is not None:
            tags = []
            for tag_def in params["tags"]:
                tag = {
                    "tag": tag_def["tag"]
                }
                if "operator" in tag_def:
                    tag["operator"] = Connector.OPERATORS[tag_def["operator"]]
                if "value" in tag_def:
                    tag["value"] = tag_def["value"]
                tags.append(tag)
            sanitized["tags"] = tags

        return zabbix_utils.helper_cleanup_data(sanitized)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        url=dict(type="str"),
        data_type=dict(type="str", choices=Connector.DATA_TYPES.keys()),
        item_value_types=dict(type="list", elements="str"),
        max_records=dict(type="int"),
        max_senders=dict(type="int"),
        max_attempts=dict(type="int"),
        attempt_interval=dict(type="str"),
        timeout=dict(type="str"),
        http_proxy=dict(type="str"),
        auth_type=dict(type="str", choices=Connector.AUTH_TYPES.keys()),
        username=dict(type="str"),
        password=dict(type="str"),
        token=dict(type="str", ),
        verify_peer=dict(type="bool"),
        verify_host=dict(type="bool"),
        ssl_cert_file=dict(type="str"),
        ssl_key_file=dict(type="str"),
        ssl_key_password=dict(type="str"),
        description=dict(type="str"),
        enabled=dict(type="bool"), # "status" in API
        tags_eval_type=dict(type="str", choices=Connector.EVAL_TYPES.keys()),
        tags=dict(
            type="list",
            elements="dict",
            options=dict(
                tag=dict(type="str", required=True),
                operator=dict(type="str", choices=Connector.OPERATORS.keys()),
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
            module.exit_json(changed=False)
    elif state == "present":
        params = connector.sanitize_params(module.params)

        if connector_id:
            connector.update_connector(connector_id, params)
        else:
            connector.add_connector(params)

if __name__ == "__main__":
    main()
