# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r'''
options:
    zabbix_credentials:
        description:
            - Zabbix connection details. A dictionary which can be used to store the connection details.
            - direct module parameters overriding zabbix_credential parameters
        suboptions:
            server_url:
                description:
                    - URL of Zabbix server, with protocol (http or https).
                required: true
                type: str
            login_user:
                description:
                    - Zabbix user name.
                required: true
                type: str
            login_password:
                description:
                    - Zabbix user password.
                required: true
                type: str
            http_login_user:
                description:
                    - Basic Auth login
                type: str
            http_login_password:
                description:
                    - Basic Auth password
                type: str
            timeout:
                description:
                    - The timeout of API request (seconds).
                type: int
                default: 10
            validate_certs:
                description:
                    - If set to False, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
                type: bool
                default: yes
        type: dict
        version_added: "0.3"
        aliases: [ connection, zabbix_connection, credentials ]
    server_url:
        description:
            - URL of Zabbix server, with protocol (http or https).
              C(url) is an alias for C(server_url).
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.server_url
        required: true
        type: str
        aliases: [ url ]
    login_user:
        description:
            - Zabbix user name.
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.login_user
        type: str
        required: true
    login_password:
        description:
            - Zabbix user password.
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.login_password
        type: str
        required: true
    http_login_user:
        description:
            - Basic Auth login
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.http_login_user
        type: str
    http_login_password:
        description:
            - Basic Auth password
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.http_login_password
        type: str
    timeout:
        description:
            - The timeout of API request (seconds).
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.timeout
        type: int
        default: 10
    validate_certs:
        description:
            - If set to False, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
            - since v0.3 can be defined centraly in zabbix_credentials
            - overrides zabbix_credentials.validate_certs
        type: bool
        default: yes
notes:
    - If you use I(login_password=zabbix), the word "zabbix" is replaced by "********" in all module output, because I(login_password) uses C(no_log).
      See L(this FAQ,https://docs.ansible.com/ansible/latest/network/user_guide/faq.html#why-is-my-output-sometimes-replaced-with) for more information.
'''
