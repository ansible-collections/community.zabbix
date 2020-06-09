import os
from zabbix_api import ZabbixAPI

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('zabbix_server')


def authenticate():
    zapi = ZabbixAPI(server='http://zabbix-server-centos/api_jsonrpc.php')
    zapi.login("Admin", "zabbix")
    return zapi


def get_hosts():
    return [
        "zabbix-agent-debian",
        "zabbix-agent-ubuntu",
        "zabbix-agent-centos",
        "zabbix-agent-docker-centos"
    ]


def test_hosts():
    zapi = authenticate()
    hosts = get_hosts()
    servers = zapi.host.get({'output': ["hostid", "name"]})

    for server in servers:
        if server['name'] != 'Zabbix server':
            assert server['name'] in hosts


def test_hosts_status():
    zapi = authenticate()
    servers = zapi.host.get({'output': ["status", "name"]})

    for server in servers:
        if server['name'] != 'Zabbix server':
            assert int(server['status']) == 0
