#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_user_directory
short_description: Create/update/delete Zabbix user directories
description:
   - This module allows you to create, modify and delete Zabbix user directories.
   - Omitted options preserve existing settings. New directories use Zabbix defaults for omitted optional settings.
   - Explicit empty strings, empty lists, false and zero values update or clear the corresponding settings.
notes:
    - Zabbix does not return the LDAP bind password. Supplying O(bind_password), including an empty string, always reports a change.
    - SAML certificates and private keys require database certificate storage in the Zabbix frontend configuration.
author:
    - Evgeny Yurchenko (@BGmot)
requirements:
    - python >= 3.9
options:
    name:
        description:
            - Unique name of the user directory.
        required: true
        type: str
    idp_type:
        description:
            - Type of IdP. Only one user directory of type SAML can exist.
            - This parameter is available since Zabbix 6.4.
            - Required when creating a directory. Existing directories retain their type when it is omitted.
        required: false
        type: str
        choices: ["ldap", "saml"]
    provision_status:
        description:
            - User directory provisioning status.
            - if I(false) Provisioning of users created by this user directory is disabled
            - if I(true) Provisioning of users created by this user directory is enabled.
              Additionally, the authentication status of C(ldap_jit_status) or C(saml_jit_status) should be enabled.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    user_username:
        description:
            - LDAP/SAML attribute name to use for users.name field when user is provisioned
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    user_lastname:
        description:
            - LDAP/SAML attribute name to use for users.surname field when user is provisioned
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    user_ref_attr:
        description:
            - LDAP user object attribute name. Will be set instead of the placeholder I(%{ref}) in c(group_filter) string.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    description:
        description:
            - User directory description.
        required: false
        type: str
    group_membership:
        description:
            - LDAP property containing groups of user. E.g. I(memberOf)
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    group_basedn:
        description:
            - LDAP groups path in LDAP tree to search for groups data.
            - Used to configure user membership check in I(openLDAP).
            - Required if group_membership is not set.
            - This parameter is available since Zabbix 6.4.
        type: str
    group_name:
        description:
            - LDAP/SAML attribute name to get group name for group mapping between Zabbix and IdP.
            - Used to configure user membership check in LDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    group_member:
        description:
            - LDAP tree attribute name containing group name received with C(group_filter) query.
            - Used to configure user membership check in openLDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        type: str
    group_filter:
        description:
            - LDAP search filter to select groups when searching for specific user groups.
            - Used to configure user membership check in openLDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        type: str
        required: false
    bind_password:
        description:
            - LDAP bind password. Can be empty for anonymous binding.
        required: false
        type: str
    search_filter:
        description:
            - LDAP custom filter string when authenticating user in LDAP.
            - Supported search_filter placeholders
            -   I(%{attr}) search attribute name (uid, sAMAccountName);
            -   I(%{user}) username value.
        required: false
        type: str
    start_tls:
        description:
            - LDAP startTLS option. It cannot be used with ldaps:// protocol hosts.
        required: false
        type: int
        choices: [0, 1]
    host:
        description:
            - LDAP server host name, IP or URI. URI should contain schema, host and port (optional).
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    port:
        description:
            - LDAP server port.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: int
    base_dn:
        description:
            - LDAP base distinguished name string.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    search_attribute:
        description:
            - LDAP attribute name to identify user by username in Zabbix database.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    bind_dn:
        description:
            - LDAP bind distinguished name string. Can be empty for anonymous binding.
        required: false
        type: str
    idp_entityid:
        description:
            - SAML URI that identifies the IdP in SAML messages.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    sp_entityid:
        description:
            - SAML SP entity ID.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    sso_url:
        description:
            - SAML URL of the IdP"s SAML SSO service, to which Zabbix will send SAML authentication requests.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    slo_url:
        description:
            - SAML IdP service endpoint URL to which Zabbix will send SAML logout requests.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    username_attribute:
        description:
            - SAML username attribute to be used in comparison with Zabbix user.username value when authenticating.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    nameid_format:
        description:
            - SAML SP name ID format.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    scim_status:
        description:
            - Whether the SCIM provisioning for SAML is enabled or disabled.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    encrypt_nameid:
        description:
            - SAML encrypt name ID. Encrypts if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    encrypt_assertions:
        description:
            - SAML encrypt assertions. Encrypts if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    sign_messages:
        description:
            - SAML sign messages. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    sign_assertions:
        description:
            - SAML sign assertions. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    sign_authn_requests:
        description:
            - SAML sign AuthN requests. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    sign_logout_requests:
        description:
            - SAML sign logout requests. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    sign_logout_responses:
        description:
            - SAML sign logout responses. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
    provision_media:
        type: list
        elements: dict
        description:
            - Array of the IdP media type mappings objects.
            - This parameter is available since Zabbix 6.4.
        suboptions:
            name:
                description:
                    - Visible name in the list of media type mappings.
                type: str
                required: true
            mediatype:
                description:
                    - Name of media type to be created.
                type: str
                required: true
            attribute:
                description:
                    - Attribute name. Used as the value for the I(sendto) field.
                    - If present in data received from IdP and the value is not empty, will trigger media creation for the provisioned user.
                type: str
                required: true
            active:
                description:
                    - Whether the provisioned media is enabled.
                type: bool
            severity:
                description:
                    - Severity bitmask for the provisioned media, from 0 to 63.
                type: int
            period:
                description:
                    - Time period when the provisioned media is active.
                type: str
    provision_groups:
        type: list
        elements: dict
        description:
            - Array of the IdP media type mappings objects.
            - This parameter is available since Zabbix 6.4.
        suboptions:
            name:
                description:
                    - IdP group full name.
                    - Supports the wildcard character "*". Unique across all provisioning groups mappings.
                type: str
                required: true
            role:
                description:
                    - User role name to assign to the user.
                    - Note that if multiple provisioning groups mappings are matched, the role of the highest user type will be assigned to the user.
                      If there are multiple roles with the same user type, the first role (sorted in alphabetical order) will be assigned to the user.
                type: str
                required: true
            user_groups:
                type: list
                elements: str
                description:
                    - Array of Zabbix user group names.
                    - Note that if multiple provisioning groups mappings are matched, Zabbix user groups of all matched mappings will be assigned to the user.
                required: true
    idp_certificate:
        description:
            - SAML identity provider certificate in PEM format.
            - Supported from Zabbix 8.0 with database certificate storage. Must not be empty when supplied.
            - Required by Zabbix when creating a SAML provider with database certificate storage.
        type: str
    sp_certificate:
        description:
            - SAML service provider certificate in PEM format.
            - Supported from Zabbix 8.0 with database certificate storage.
            - An empty string clears it when SAML signing and encryption options are disabled.
        type: str
    sp_private_key:
        description:
            - SAML service provider private key in PEM format.
            - Supported from Zabbix 8.0 with database certificate storage.
            - An empty string clears it when SAML signing and encryption options are disabled.
        type: str
    state:
        description:
            - State of the user directory.
            - On C(present), it will create if user directory does not exist or update it if the associated data is different.
            - On C(absent) will remove the user directory if it exists.
        choices: ["present", "absent"]
        default: "present"
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix

"""

EXAMPLES = r"""
---
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

- name: Create new user directory or update existing info (Zabbix <= 6.2)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    host: "test.com"
    port: 389
    base_dn: "ou=Users,dc=example,dc=org"
    search_attribute: "uid"
    bind_dn: "cn=ldap_search,dc=example,dc=org"
    description: "Test user directory"
    search_filter: "(%{attr}=test_user)"
    start_tls: 0

- name: Create new user directory with LDAP IDP or update existing info (Zabbix >= 6.4)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    idp_type: ldap
    host: "test.ca"
    port: 389
    base_dn: "ou=Users,dc=example,dc=org"
    search_attribute: "uid"
    provision_status: true
    group_name: cn
    group_basedn: ou=Group,dc=example,dc=org
    group_member: member
    user_ref_attr: uid
    group_filter: "(member=uid=%{ref},ou=Users,dc=example,dc=com)"
    user_username: first_name
    user_lastname: last_name
    provision_media:
      - name: Media1
        mediatype: Email
        attribute: email1
    provision_groups:
      - name: idpname1
        role: Guest role
        user_groups:
          - Guests

- name: Create new user directory with SAML IDP or update existing info (Zabbix >= 6.4)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    idp_type: saml
    idp_entityid: http://okta.com/xxxxx
    sp_entityid: zabbix
    sso_url: http://xxxx.okta.com/app/xxxxxx_123dhu8o3
    username_attribute: usrEmail
    provision_status: true
    group_name: cn
    user_username: first_name
    user_lastname: last_name
    provision_media:
      - name: Media1
        mediatype: Email
        attribute: email1
    provision_groups:
      - name: idpname1
        role: Guest role
        user_groups:
          - Guests
# Zabbix 8.0 database certificate storage
- name: Create a SAML provider with certificates
  community.zabbix.zabbix_user_directory:
    name: Corporate SAML
    idp_type: saml
    idp_entityid: https://idp.example.com
    sp_entityid: https://zabbix.example.com
    sso_url: https://idp.example.com/sso
    username_attribute: uid
    idp_certificate: "{{ lookup('ansible.builtin.file', 'idp.pem', rstrip=False) }}"
    sp_certificate: "{{ lookup('ansible.builtin.file', 'sp.pem', rstrip=False) }}"
    sp_private_key: "{{ lookup('ansible.builtin.file', 'sp-key.pem', rstrip=False) }}"

- name: Disable StartTLS on an existing LDAP provider
  community.zabbix.zabbix_user_directory:
    name: Corporate LDAP
    start_tls: 0
"""

RETURN = r"""
result:
    description: Description of the operation performed.
    returned: success
    type: str
"""

import hashlib

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            idp_type=dict(type="str", required=False, choices=["ldap", "saml"]),
            host=dict(type="str", required=False),
            port=dict(type="int", required=False),
            base_dn=dict(type="str", required=False),
            search_attribute=dict(type="str", required=False),
            bind_dn=dict(type="str", required=False),
            bind_password=dict(type="str", required=False, no_log=True),
            description=dict(type="str", required=False),
            search_filter=dict(type="str", required=False),
            start_tls=dict(type="int", required=False, choices=[0, 1]),
            idp_entityid=dict(type="str", required=False),
            sp_entityid=dict(type="str", required=False),
            sso_url=dict(type="str", required=False),
            slo_url=dict(type="str", required=False),
            username_attribute=dict(type="str", required=False),
            nameid_format=dict(type="str", required=False),
            scim_status=dict(type="bool", required=False),
            encrypt_nameid=dict(type="bool", required=False),
            encrypt_assertions=dict(type="bool", required=False),
            sign_messages=dict(type="bool", required=False),
            sign_assertions=dict(type="bool", required=False),
            sign_authn_requests=dict(type="bool", required=False),
            sign_logout_requests=dict(type="bool", required=False),
            sign_logout_responses=dict(type="bool", required=False),
            provision_status=dict(type="bool", required=False),
            group_basedn=dict(type="str", required=False),
            group_filter=dict(type="str", required=False),
            group_member=dict(type="str", required=False),
            group_membership=dict(type="str", required=False),
            group_name=dict(type="str", required=False),
            user_lastname=dict(type="str", required=False),
            user_ref_attr=dict(type="str", required=False),
            user_username=dict(type="str", required=False),
            provision_media=dict(
                type="list",
                required=False,
                elements="dict",
                options=dict(
                    name=dict(type="str", required=True),
                    mediatype=dict(type="str", required=True),
                    attribute=dict(type="str", required=True),
                    active=dict(type="bool"),
                    severity=dict(type="int"),
                    period=dict(type="str"),
                ),
            ),
            provision_groups=dict(
                type="list",
                required=False,
                elements="dict",
                options=dict(
                    name=dict(type="str", required=True),
                    role=dict(type="str", required=True),
                    user_groups=dict(type="list", elements="str", required=True),
                ),
            ),
            idp_certificate=dict(type="str"),
            sp_certificate=dict(type="str"),
            sp_private_key=dict(type="str", no_log=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    user_directory = ZabbixBase(module)
    if LooseVersion(user_directory._zbx_api_version) < LooseVersion("7.0"):
        module.fail_json(msg="Zabbix < 7.0 does not support user directories.")

    name = module.params["name"]
    state = module.params["state"]
    directories = user_directory._zapi.userdirectory.get({
        "search": {"name": name},
        "selectProvisionMedia": "extend",
        "selectProvisionGroups": "extend",
    })
    directories = [directory for directory in directories if directory.get("name") == name]
    current = directories[0] if directories else {}
    if state == "absent":
        if current and not module.check_mode:
            user_directory._zapi.userdirectory.delete([current["userdirectoryid"]])
        module.exit_json(changed=bool(current), result="User directory removed or already absent: %s" % name)

    idp_type = module.params["idp_type"] or {"1": "ldap", "2": "saml"}.get(str(current.get("idp_type")))
    if idp_type is None:
        module.fail_json(msg="idp_type must be provided when creating a user directory")
    if current and str(current["idp_type"]) != {"ldap": "1", "saml": "2"}[idp_type]:
        module.fail_json(msg="The idp_type of an existing user directory cannot be changed")

    ldap_fields = (
        "host", "port", "base_dn", "search_attribute", "bind_dn", "bind_password", "description", "start_tls",
        "search_filter", "group_basedn", "group_filter", "group_member", "group_membership", "user_ref_attr",
    )
    saml_fields = (
        "idp_entityid", "sso_url", "username_attribute", "sp_entityid", "slo_url", "nameid_format", "scim_status",
        "encrypt_nameid", "encrypt_assertions", "sign_messages", "sign_assertions", "sign_authn_requests",
        "sign_logout_requests", "sign_logout_responses", "idp_certificate", "sp_certificate", "sp_private_key",
    )
    for field in saml_fields if idp_type == "ldap" else ldap_fields:
        if module.params[field] is not None:
            module.fail_json(msg="%s is not supported for an %s user directory" % (field, idp_type))

    parameters = {"name": name}
    if not current:
        parameters["idp_type"] = {"ldap": 1, "saml": 2}[idp_type]
    fields = (ldap_fields if idp_type == "ldap" else saml_fields) + ("group_name", "user_lastname", "user_username", "provision_status")
    for field in fields:
        value = module.params[field]
        if value is not None:
            parameters[field] = int(value) if isinstance(value, bool) else value
    for field in ("idp_certificate", "sp_certificate", "sp_private_key"):
        if field in parameters and LooseVersion(user_directory._zbx_api_version) < LooseVersion("8.0"):
            module.fail_json(msg="%s is supported from Zabbix 8.0" % field)

    future = dict(current, **parameters)
    if idp_type == "saml":
        if parameters.get("idp_certificate") == "":
            module.fail_json(msg="idp_certificate must not be empty")
        signing_fields = (
            "sign_messages", "sign_assertions", "sign_authn_requests", "sign_logout_requests", "sign_logout_responses",
            "encrypt_nameid", "encrypt_assertions",
        )
        if any(str(future.get(field, "0")) == "1" for field in signing_fields):
            for field in ("sp_certificate", "sp_private_key"):
                if parameters.get(field) == "":
                    module.fail_json(msg="%s cannot be cleared while SAML signing or encryption is enabled" % field)
    mandatory = ("host", "port", "base_dn", "search_attribute") if idp_type == "ldap" else ("idp_entityid", "sp_entityid", "sso_url", "username_attribute")
    for field in mandatory:
        if not future.get(field):
            module.fail_json(msg="%s is required for an %s user directory" % (field, idp_type))
    if idp_type == "ldap":
        if not 1 <= int(future["port"]) <= 65535:
            module.fail_json(msg="port must be between 1 and 65535")
        if str(future.get("start_tls", "0")) == "1" and future["host"].lower().startswith("ldaps://"):
            module.fail_json(msg="start_tls cannot be enabled for an ldaps:// host")

    provisioning = str(future.get("provision_status", "0")) == "1"
    for field in ("provision_media", "provision_groups"):
        values = module.params[field]
        if values is None:
            continue
        if values and not provisioning:
            module.fail_json(msg="provision_status must be true to define %s" % field)
        parameters[field] = []
        seen_names = set()
        for mapping in values:
            if mapping["name"] in seen_names:
                module.fail_json(msg="%s must not contain duplicate mapping names" % field)
            seen_names.add(mapping["name"])
            if field == "provision_media":
                media = user_directory._zapi.mediatype.get({"filter": {"name": mapping["mediatype"]}})
                if not media:
                    module.fail_json(msg="Mediatype '%s' cannot be found" % mapping["mediatype"])
                item = {"name": mapping["name"], "mediatypeid": media[0]["mediatypeid"], "attribute": mapping["attribute"]}
                for option in ("active", "severity", "period"):
                    if mapping[option] is not None:
                        item[option] = int(not mapping[option]) if option == "active" else mapping[option]
                if "severity" in item and not 0 <= item["severity"] <= 63:
                    module.fail_json(msg="provision_media severity must be between 0 and 63")
            else:
                if len(mapping["user_groups"]) != len(set(mapping["user_groups"])):
                    module.fail_json(msg="provision_groups user_groups must not contain duplicates")
                roles = user_directory._zapi.role.get({"filter": {"name": mapping["role"]}})
                if not roles:
                    module.fail_json(msg="Role '%s' cannot be found" % mapping["role"])
                groups = []
                for group in mapping["user_groups"]:
                    matches = user_directory._zapi.usergroup.get({"filter": {"name": group}})
                    if not matches:
                        module.fail_json(msg="User group '%s' cannot be found" % group)
                    groups.append({"usrgrpid": matches[0]["usrgrpid"]})
                item = {"name": mapping["name"], "roleid": roles[0]["roleid"], "user_groups": groups}
            parameters[field].append(item)

    if provisioning and not parameters.get("provision_groups", current.get("provision_groups")):
        module.fail_json(msg="provision_groups is required when provision_status is true")

    comparison = zabbix_utils.helper_convert_unicode_to_str(parameters)
    existing = zabbix_utils.helper_convert_unicode_to_str(current)
    for field in ("idp_certificate", "sp_certificate", "sp_private_key"):
        if field in comparison:
            if current and field + "_hash" not in existing:
                module.fail_json(msg="%s requires database certificate storage in the Zabbix frontend" % field)
            value = parameters[field]
            # Match the checksum exposed by the Zabbix API for write-only certificate fields.
            digest = hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest() if value else ""
            existing[field] = comparison[field] if existing.get(field + "_hash") == digest else None
    difference = zabbix_utils.helper_compare_dictionaries(comparison, existing, {})
    if not difference:
        module.exit_json(changed=False, result="User directory %s is up to date" % name)
    if not module.check_mode:
        try:
            if current:
                update = {field: parameters[field] for field in difference}
                update["userdirectoryid"] = current["userdirectoryid"]
                user_directory._zapi.userdirectory.update(update)
            else:
                user_directory._zapi.userdirectory.create(parameters)
        except Exception as e:
            module.fail_json(msg="Failed to configure user directory '%s': %s" % (name, e))
    module.exit_json(changed=True, result="User directory %s configured" % name)


if __name__ == "__main__":
    main()
