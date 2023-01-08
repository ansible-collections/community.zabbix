# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r'''
options:
    server_url:
        description:
            - URL of Zabbix server, with protocol (http or https).
              C(url) is an alias for C(server_url).
            - If not set the environment variable C(ZABBIX_SERVER) will be used.
            - This option is deprecated with the move to httpapi connection and will be removed in the next release
        required: false
        type: str
        aliases: [ url ]
    login_user:
        description:
            - Zabbix user name.
            - If not set the environment variable C(ZABBIX_USERNAME) will be used.
            - This option is deprecated with the move to httpapi connection and will be removed in the next release
        type: str
        required: false
    login_password:
        description:
            - Zabbix user password.
            - If not set the environment variable C(ZABBIX_PASSWORD) will be used.
            - This option is deprecated with the move to httpapi connection and will be removed in the next release
        type: str
        required: false
    http_login_user:
        description:
            - Basic Auth login
        type: str
        required: false
    http_login_password:
        description:
            - Basic Auth password
        type: str
        required: false
    timeout:
        description:
            - The timeout of API request (seconds).
            - This option is deprecated with the move to httpapi connection and will be removed in the next release
            - The default value is C(10)
        type: int
    validate_certs:
        description:
            - If set to False, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
            - If not set the environment variable C(ZABBIX_VALIDATE_CERTS) will be used.
            - This option is deprecated with the move to httpapi connection and will be removed in the next release
            - The default value is C(true)
        type: bool
notes:
    - If you use I(login_password=zabbix), the word "zabbix" is replaced by "********" in all module output, because I(login_password) uses C(no_log).
      See L(this FAQ,https://docs.ansible.com/ansible/latest/network/user_guide/faq.html#why-is-my-output-sometimes-replaced-with) for more information.
'''
