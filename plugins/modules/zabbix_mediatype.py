#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_mediatype
short_description: Create/Update/Delete Zabbix media types
description:
    - This module allows you to create, modify and delete Zabbix media types.
author:
    - Ruben Tsirunyan (@rubentsirunyan)
requirements:
    - "python >= 3.9"

options:
    name:
        type: "str"
        description:
            - Name of the media type.
        required: true
    description:
        type: "str"
        description:
            - Description of the media type.
        default: ""
    state:
        type: "str"
        description:
            - Desired state of the mediatype.
            - On C(present), it will create a mediatype if it does not exist or update the mediatype if the associated data is different.
            - On C(absent), it will remove the mediatype if it exists.
        choices:
            - present
            - absent
        default: "present"
    type:
        type: "str"
        description:
            - Type of the media type.
            - Media types I(jabber) and I(ez_texting) works only with Zabbix versions 4.2 or older.
        choices:
            - email
            - script
            - sms
            - webhook
            - jabber
            - ez_texting
        required: true
    status:
        type: "str"
        description:
            - Whether the media type is enabled or no.
        choices:
            - enabled
            - disabled
        default: "enabled"
    max_sessions:
        type: "int"
        description:
            - The maximum number of alerts that can be processed in parallel.
            - Possible value is 1 when I(type=sms) and 0-100 otherwise.
        default: 1
    max_attempts:
        type: "int"
        description:
            - The maximum number of attempts to send an alert.
            - Possible range is 0-10.
        default: 3
    attempt_interval:
        type: "str"
        description:
            - The interval between retry attempts.
            - Possible range is 0-1h.
        default: 10s
    script_name:
        type: "str"
        description:
            - The name of the executed script.
            - Required when I(type=script).
    script_params:
        type: "list"
        elements: str
        description:
            - List of script parameters.
            - Required when I(type=script).
    gsm_modem:
        type: "str"
        description:
            - Serial device name of the gsm modem.
            - Required when I(type=sms).
    username:
        type: "str"
        description:
            - Username or Jabber identifier.
            - Required when I(type=jabber) or I(type=ez_texting).
            - Required when I(type=email) and I(smtp_authentication=true).
    password:
        type: "str"
        description:
            - Authentication password.
            - Required when I(type=jabber) or I(type=ez_texting).
            - Required when I(type=email) and I(smtp_authentication=true).
    smtp_server:
        type: "str"
        description:
            - SMTP server host.
            - Required when I(type=email).
        default: "localhost"
    smtp_server_port:
        type: "int"
        description:
            - SMTP server port.
            - Required when I(type=email).
        default: 25
    smtp_helo:
        type: "str"
        description:
            - SMTP HELO.
            - Required when I(type=email).
        default: "localhost"
    smtp_email:
        type: "str"
        description:
            - Email address from which notifications will be sent.
            - Required when I(type=email).
    smtp_authentication:
        type: "bool"
        description:
            - Whether SMTP authentication with username and password should be enabled or not.
            - If set to C(true), C(username) and C(password) should be specified.
        default: false
    smtp_security:
        type: "str"
        description:
            - SMTP connection security level to use.
        choices:
            - None
            - STARTTLS
            - SSL/TLS
    smtp_verify_host:
        type: "bool"
        description:
            - SSL verify host for SMTP.
            - Can be specified when I(smtp_security=STARTTLS) or I(smtp_security=SSL/TLS)
        default: false
    smtp_verify_peer:
        type: "bool"
        description:
            - SSL verify peer for SMTP.
            - Can be specified when I(smtp_security=STARTTLS) or I(smtp_security=SSL/TLS)
        default: false
    message_format:
        type: "str"
        description:
            - Can be used when I(type=email).
        choices:
            - plaintext
            - html
        default: html
        aliases: ["content_type"]
    message_text_limit:
        type: "str"
        description:
            - The message text limit.
            - Required when I(type=ez_texting).
            - 160 characters for USA and 136 characters for Canada.
        choices:
            - USA
            - Canada
    webhook_script:
        type: "str"
        description:
            - Required when I(type=webhook).
            - JavaScript code that will perform webhook operation.
            - This code has access to all parameters in I(webhook_params).
            - It may perform HTTP GET, POST, PUT and DELETE requests and has control over HTTP headers and request body.
            - It may return OK status along with an optional list of tags and tag values or an error string.
    webhook_timeout:
        type: "str"
        description:
            - Can be used when I(type=webhook).
            - Execution timeout for JavaScript code in I(webhook_script).
            - Possible values are 1-60s.
        default: 30s
    process_tags:
        type: "bool"
        description:
            - Can be used when I(type=webhook).
            - Process returned JSON property values as tags.
            - These tags are added to the already existing (if any) problem event tags in Zabbix.
        default: false
    event_menu:
        type: "bool"
        description:
            - Can be used when I(type=webhook).
            - Includes entry in Event menu with link to created external ticket.
        default: false
    event_menu_url:
        type: "str"
        description:
            - Requred when I(event_menu=true).
            - Event menu entry underlying URL.
    event_menu_name:
        type: "str"
        description:
            - Requred when I(event_menu=true).
            - Event menu entry name.
    webhook_params:
        type: "list"
        elements: "dict"
        description:
            - Can be used when I(type=webhook).
            - Webhook variables that are passed to webhook script when executed.
        default: []
        suboptions:
            name:
                type: "str"
                description:
                    - Name of the parameter.
                required: true
            value:
                type: "str"
                description:
                    - Value of the parameter.
                    - All macros that are supported in problem notifications are supported in the parameters.
                    - Values are URL-encoded automatically. Values from macros are resolved and then URL-encoded automatically.
                default: ""
    message_templates:
        type: "list"
        elements: "dict"
        description:
            - Default notification messages for the event types.
        default: []
        suboptions:
            eventsource:
                type: "str"
                description:
                    - Event source.
                    - Required when I(recovery) is used.
                choices:
                    - triggers
                    - discovery
                    - autoregistration
                    - internal
                    - services
            recovery:
                type: "str"
                description:
                    - Operation mode.
                    - Required when I(eventsource) is used.
                choices:
                    - operations
                    - recovery_operations
                    - update_operations
            subject:
                type: "str"
                description:
                    - Subject of the default message.
                    - May contain macros and is limited to 255 characters.
                default: ""
            body:
                type: "str"
                description:
                    - Body of the default message.
                    - May contain macros.
                default: ""

extends_documentation_fragment:
- community.zabbix.zabbix


"""

RETURN = r""" # """

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

- name: "Create an email mediatype with SMTP authentication"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "Ops email"
    type: "email"
    smtp_server: "example.com"
    smtp_server_port: 2000
    smtp_email: "ops@example.com"
    smtp_authentication: true
    username: "smtp_user"
    password: "smtp_pass"

- name: "Create a script mediatype"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "my script"
    type: "script"
    script_name: "my_script.py"
    script_params:
      - "arg1"
      - "arg2"

- name: "Create a jabber mediatype"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "My jabber"
    type: "jabber"
    username: "jabber_id"
    password: "jabber_pass"

- name: "Create a SMS mediatype"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "My SMS Mediatype"
    type: "sms"
    gsm_modem: "/dev/ttyS0"

- name: "Create a webhook mediatype"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "My webhook Mediatype"
    type: "webhook"
    webhook_script: "{{ lookup('file', 'slack.js') }}"
    webhook_params:
      - name: alert_message
        value: "{ALERT.MESSAGE}"
      - name: zabbix_url
        value: "{$ZABBIX.URL}"
    process_tags: true
    event_menu: true
    event_menu_name: "Open in Slack: '{EVENT.TAGS.__channel_name}'"
    event_menu_url: "{EVENT.TAGS.__message_link}"

- name: "Create an email mediatype with message templates"
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mediatype:
    name: "Ops email"
    type: "email"
    smtp_email: "ops@example.com"
    message_templates:
      - eventsource: triggers
        recovery: operations
        subject: "Problem: {EVENT.NAME}"
        body: "Problem started at {EVENT.TIME} on {EVENT.DATE}\r\nProblem name: {EVENT.NAME}\r\n"
      - eventsource: triggers
        recovery: recovery_operations
        subject: "Resolved: {EVENT.NAME}"
        body: "Problem resolved at {EVENT.TIME} on {EVENT.DATE}\r\nProblem name: {EVENT.NAME}\r\n"
      - eventsource: triggers
        recovery: update_operations
        subject: "Updated problem: {EVENT.NAME}"
        body: "{USER.FULLNAME} {EVENT.UPDATE.ACTION} problem at {EVENT.UPDATE.DATE} {EVENT.UPDATE.TIME}.\r\n"
      - eventsource: discovery
        recovery: operations
        subject: "Discovery: {DISCOVERY.DEVICE.STATUS} {DISCOVERY.DEVICE.IPADDRESS}"
        body: "Discovery rule: {DISCOVERY.RULE.NAME}\r\n\r\nDevice IP: {DISCOVERY.DEVICE.IPADDRESS}"
      - eventsource: autoregistration
        recovery: operations
        subject: "Autoregistration: {HOST.HOST}"
        body: "Host name: {HOST.HOST}\r\nHost IP: {HOST.IP}\r\nAgent port: {HOST.PORT}"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def diff(existing, new):
    """Constructs the diff for Ansible's --diff option.

    Args:
        existing (dict): Existing mediatype data.
        new (dict): New mediatype data.

    Returns:
        A dictionary like {'before': existing, 'after': new}
        with filtered empty values.
    """
    before = {}
    after = {}
    for key in new:
        before[key] = existing[key]
        if new[key] is None:
            after[key] = ""
        else:
            after[key] = new[key]
    return {"before": before, "after": after}


class MediaTypeModule(ZabbixBase):
    def check_if_mediatype_exists(self, name):
        """Checks if mediatype exists.

        Args:
            name: Zabbix mediatype name

        Returns:
            Tuple of (True, `id of the mediatype`) if mediatype exists, (False, None) otherwise
        """
        filter_key_name = "description"
        filter_key_name = "name"

        try:
            mediatype_list = self._zapi.mediatype.get({
                "output": "extend",
                "filter": {filter_key_name: [name]}
            })
            if len(mediatype_list) < 1:
                return False, None
            else:
                return True, mediatype_list[0]["mediatypeid"]
        except Exception as e:
            self._module.fail_json(msg="Failed to get ID of the mediatype '{name}': {e}".format(name=name, e=e))

    def construct_parameters(self):
        """Translates data to a format suitable for Zabbix API and filters
        the ones that are related to the specified mediatype type.

        Returns:
            A dictionary of arguments that are related to transport type,
            and are in a format that is understandable by Zabbix API.
        """
        truths = {"False": "0", "True": "1"}
        parameters = dict(
            status="0" if self._module.params["status"] == "enabled" else "1",
            type={
                "email": "0",
                "script": "1",
                "sms": "2",
                "jabber": "3",
                "webhook": "4",
                "ez_texting": "100"
            }.get(self._module.params["type"]),
        )

        parameters.update(dict(
            name=self._module.params["name"],
            description=self._module.params["description"],
            maxsessions=str(self._module.params["max_sessions"]),
            maxattempts=str(self._module.params["max_attempts"]),
            attempt_interval=str(self._module.params["attempt_interval"])
        ))

        if self._module.params["message_templates"]:
            msg_templates = []
            for template in self._module.params["message_templates"]:
                msg_templates.append(dict(
                    eventsource={
                        "triggers": "0",
                        "discovery": "1",
                        "autoregistration": "2",
                        "internal": "3",
                        "services": "4"}.get(template["eventsource"]),
                    recovery={
                        "operations": "0",
                        "recovery_operations": "1",
                        "update_operations": "2"}.get(template["recovery"]),
                    subject=template["subject"],
                    message=template["body"]
                ))
            parameters.update(dict(message_templates=msg_templates))

        if self._module.params["type"] == "email":
            parameters.update(dict(
                smtp_server=self._module.params["smtp_server"],
                smtp_port=str(self._module.params["smtp_server_port"]),
                smtp_helo=self._module.params["smtp_helo"],
                smtp_email=self._module.params["smtp_email"],
                smtp_security={"None": "0", "STARTTLS": "1", "SSL/TLS": "2"}.get(str(self._module.params["smtp_security"])),
                smtp_authentication=truths.get(str(self._module.params["smtp_authentication"])),
                smtp_verify_host=truths.get(str(self._module.params["smtp_verify_host"])),
                smtp_verify_peer=truths.get(str(self._module.params["smtp_verify_peer"])),
                message_format={"plaintext": "0", "html": "1"}.get(str(self._module.params["message_format"])),
                username=self._module.params["username"],
                passwd=self._module.params["password"]
            ))
            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                parameters["content_type"] = parameters["message_format"]
                del parameters["message_format"]
            if parameters["smtp_authentication"] == "0":
                parameters.pop("username")
                parameters.pop("passwd")
            return parameters

        elif self._module.params["type"] == "script":
            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                if self._module.params["script_params"] is None:
                    _script_params = ""  # ZBX-15706
                else:
                    _script_params = "\n".join(str(i) for i in self._module.params["script_params"]) + "\n"
                parameters.update(dict(
                    exec_path=self._module.params["script_name"],
                    exec_params=_script_params
                ))
            else:
                _script_params = []
                if self._module.params["script_params"]:
                    for i, val in enumerate(self._module.params["script_params"]):
                        _script_params.append({"sortorder": str(i), "value": val})
                parameters.update(dict(
                    exec_path=self._module.params["script_name"],
                    parameters=_script_params
                ))
            return parameters

        elif self._module.params["type"] == "sms":
            parameters.update(dict(gsm_modem=self._module.params["gsm_modem"]))
            return parameters

        elif self._module.params["type"] == "webhook":
            parameters.update(dict(
                script=self._module.params["webhook_script"],
                timeout=self._module.params["webhook_timeout"],
                process_tags=truths.get(str(self._module.params["process_tags"])),
                show_event_menu=truths.get(str(self._module.params["event_menu"])),
                parameters=self._module.params["webhook_params"]
            ))
            if self._module.params["event_menu"]:
                parameters.update(dict(
                    event_menu_url=self._module.params["event_menu_url"],
                    event_menu_name=self._module.params["event_menu_name"]
                ))
            return parameters

        self._module.fail_json(msg="%s is unsupported for Zabbix version %s" % (self._module.params["type"], self._zbx_api_version))

    def validate_params(self, params):
        """Validates arguments that are required together.

        Fails the module with the message that shows the missing
        requirements if there are some.

        Args:
            params (list): Each element of this list
                is a list like
                ['argument_key', 'argument_value', ['required_arg_1',
                                                    'required_arg_2']].
                Format is the same as `required_if` parameter of AnsibleModule.
        """
        for param in params:
            if self._module.params[param[0]] == param[1]:
                if None in [self._module.params[i] for i in param[2]]:
                    self._module.fail_json(
                        msg="Following arguments are required when {key} is {value}: {arguments}".format(
                            key=param[0],
                            value=param[1],
                            arguments=", ".join(param[2])
                        )
                    )

    def get_update_params(self, mediatype_id, **kwargs):
        """Filters only the parameters that are different and need to be updated.

        Args:
            mediatype_id (int): ID of the mediatype to be updated.
            **kwargs: Parameters for the new mediatype.

        Returns:
            A tuple where the first element is a dictionary of parameters
            that need to be updated and the second one is a dictionary
            returned by diff() function with
            existing mediatype data and new params passed to it.
        """
        get_params = {
            "output": "extend",
            "mediatypeids": [mediatype_id],
            "selectMessageTemplates": "extend"
        }

        existing_mediatype = self._zapi.mediatype.get(get_params)[0]

        if existing_mediatype["type"] != kwargs["type"]:
            return kwargs, diff(existing_mediatype, kwargs)
        else:
            params_to_update = {}
            for key in kwargs:
                # sort list of parameters to prevent mismatch due to reordering
                if key == "parameters" and (kwargs[key] != [] or existing_mediatype[key] != []):
                    if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                        kwargs[key] = sorted(kwargs[key], key=lambda x: x["name"])
                        existing_mediatype[key] = sorted(existing_mediatype[key], key=lambda x: x["name"])
                    else:
                        if kwargs["type"] == "1":  # script
                            kwargs[key] = sorted(kwargs[key], key=lambda x: x["sortorder"])
                            existing_mediatype[key] = sorted(existing_mediatype[key], key=lambda x: x["sortorder"])
                        elif kwargs["type"] == "4":  # webhook
                            kwargs[key] = sorted(kwargs[key], key=lambda x: x["name"])
                            existing_mediatype[key] = sorted(existing_mediatype[key], key=lambda x: x["name"])

                if key == "message_templates" and (kwargs[key] != [] or existing_mediatype[key] != []):
                    kwargs[key] = sorted(kwargs[key], key=lambda x: x["subject"])
                    existing_mediatype[key] = sorted(existing_mediatype[key], key=lambda x: x["subject"])

                if (not (kwargs[key] is None and existing_mediatype[key] == "")) and kwargs[key] != existing_mediatype[key]:
                    params_to_update[key] = kwargs[key]
            return params_to_update, diff(existing_mediatype, kwargs)

    def delete_mediatype(self, mediatype_id):
        try:
            return self._zapi.mediatype.delete([mediatype_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete mediatype '{_id}': {e}".format(_id=mediatype_id, e=e))

    def update_mediatype(self, **kwargs):
        try:
            self._zapi.mediatype.update(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to update mediatype '{_id}': {e}".format(_id=kwargs["mediatypeid"], e=e))

    def create_mediatype(self, **kwargs):
        try:
            self._zapi.mediatype.create(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to create mediatype '{name}': {e}".format(name=kwargs["name"], e=e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        description=dict(type="str", required=False, default=""),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        type=dict(type="str", choices=["email", "script", "sms", "webhook", "jabber", "ez_texting"], required=True),
        status=dict(type="str", default="enabled", choices=["enabled", "disabled"], required=False),
        max_sessions=dict(type="int", default=1, required=False),
        max_attempts=dict(type="int", default=3, required=False),
        attempt_interval=dict(type="str", default="10s", required=False),
        # Script
        script_name=dict(type="str", required=False),
        script_params=dict(type="list", required=False, elements="str"),
        # SMS
        gsm_modem=dict(type="str", required=False),
        # Jabber
        username=dict(type="str", required=False),
        password=dict(type="str", required=False, no_log=True),
        # Email
        smtp_server=dict(type="str", default="localhost", required=False),
        smtp_server_port=dict(type="int", default=25, required=False),
        smtp_helo=dict(type="str", default="localhost", required=False),
        smtp_email=dict(type="str", required=False),
        smtp_security=dict(type="str", required=False, choices=["None", "STARTTLS", "SSL/TLS"]),
        smtp_authentication=dict(type="bool", default=False, required=False),
        smtp_verify_host=dict(type="bool", default=False, required=False),
        smtp_verify_peer=dict(type="bool", default=False, required=False),
        message_format=dict(type="str", choices=["plaintext", "html"], default="html", required=False, aliases=["content_type"]),
        # EZ Text
        message_text_limit=dict(type="str", required=False, choices=["USA", "Canada"]),
        # Webhook
        webhook_script=dict(type="str"),
        webhook_timeout=dict(type="str", default="30s"),
        process_tags=dict(type="bool", default=False),
        event_menu=dict(type="bool", default=False),
        event_menu_url=dict(type="str"),
        event_menu_name=dict(type="str"),
        webhook_params=dict(
            type="list",
            elements="dict",
            default=[],
            required=False,
            options=dict(
                name=dict(type="str", required=True),
                value=dict(type="str", default="")
            )
        ),
        message_templates=dict(
            type="list",
            elements="dict",
            default=[],
            required=False,
            options=dict(
                eventsource=dict(type="str", choices=["triggers", "discovery", "autoregistration", "internal", "services"]),
                recovery=dict(type="str", choices=["operations", "recovery_operations", "update_operations"]),
                subject=dict(type="str", default=""),
                body=dict(type="str", default="")
            ),
            required_together=[
                ["eventsource", "recovery"]
            ],
        )
    ))

    # this is used to simulate `required_if` of `AnsibleModule`, but only when state=present
    required_params = [
        ["type", "email", ["smtp_email"]],
        ["type", "script", ["script_name"]],
        ["type", "sms", ["gsm_modem"]],
        ["type", "jabber", ["username", "password"]],
        ["type", "ez_texting", ["username", "password", "message_text_limit"]],
        ["type", "webhook", ["webhook_script"]],
        ["event_menu", True, ["event_menu_url", "event_menu_name"]],
        ["smtp_authentication", True, ["username", "password"]]
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    state = module.params["state"]
    name = module.params["name"]

    mediatype = MediaTypeModule(module)
    if module.params["state"] == "present":
        mediatype.validate_params(required_params)
    mediatype_exists, mediatype_id = mediatype.check_if_mediatype_exists(name)

    parameters = mediatype.construct_parameters()

    if mediatype_exists:
        if state == "absent":
            if module.check_mode:
                module.exit_json(
                    changed=True,
                    msg="Mediatype would have been deleted. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=mediatype_id
                    )
                )
            mediatype_id = mediatype.delete_mediatype(mediatype_id)
            module.exit_json(
                changed=True,
                msg="Mediatype deleted. Name: {name}, ID: {_id}".format(
                    name=name,
                    _id=mediatype_id
                )
            )
        else:
            params_to_update, diff = mediatype.get_update_params(mediatype_id, **parameters)
            if params_to_update == {}:
                module.exit_json(
                    changed=False,
                    msg="Mediatype is up to date: {name}".format(name=name)
                )
            else:
                if module.check_mode:
                    module.exit_json(
                        changed=True,
                        diff=diff,
                        msg="Mediatype would have been updated. Name: {name}, ID: {_id}".format(
                            name=name,
                            _id=mediatype_id
                        )
                    )
                mediatype_id = mediatype.update_mediatype(mediatypeid=mediatype_id, **params_to_update)
                module.exit_json(
                    changed=True,
                    diff=diff,
                    msg="Mediatype updated. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=mediatype_id
                    )
                )
    else:
        if state == "absent":
            module.exit_json(changed=False)
        else:
            if module.check_mode:
                module.exit_json(
                    changed=True,
                    msg="Mediatype would have been created. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=mediatype_id
                    )
                )
            mediatype_id = mediatype.create_mediatype(**parameters)
            module.exit_json(
                changed=True,
                msg="Mediatype created: {name}, ID: {_id}".format(
                    name=name,
                    _id=mediatype_id
                )
            )


if __name__ == "__main__":
    main()
