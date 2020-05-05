import os
from zabbix_api import ZabbixAPI

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('zabbix_agent')


def authenticate():
    zapi = ZabbixAPI(server='http://zabbix-server-centos/api_jsonrpc.php')
    zapi.login("Admin", "zabbix")
    return zapi


def test_psk_host(host):
    zapi = authenticate()
    hostname = host.check_output('hostname -s')
    host_name = "zabbix-agent-ubuntu"

    server_data = zapi.host.get({'output': 'extend', 'selectInventory': 'extend', 'filter': {'host': [hostname]}})

    if hostname == host_name:
        assert server_data[0]['tls_psk'] == "b7e3d380b9d400676d47198ecf3592ccd4795a59668aa2ade29f0003abbbd40d"
        assert server_data[0]['tls_psk_identity'] == "myhost PSK"
        assert server_data[0]['tls_accept'] == "2"
    else:
        assert server_data[0]['tls_psk'] == ""
        assert server_data[0]['tls_psk_identity'] == ""
        assert server_data[0]['tls_accept'] == "1"


def test_zabbix_agent_psk(host):
    hostname = host.check_output('hostname -s')
    host_name = "zabbix-agent-ubuntu"

    psk_file = host.file("/etc/zabbix/zabbix_agent_pskfile.psk")
    if hostname == host_name:
        assert psk_file.user == "zabbix"
        assert psk_file.group == "zabbix"
        assert psk_file.mode == 0o400
        assert psk_file.contains("b7e3d380b9d400676d47198ecf3592ccd4795a59668aa2ade29f0003abbbd40d")
    else:
        assert not psk_file.exists
