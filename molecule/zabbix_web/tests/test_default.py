import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.mark.parametrize("server, redhat, debian", [
    ("zabbix-server-pgsql", "zabbix-web-pgsql", "zabbix-frontend-php"),
    ("zabbix-server-mysql", "zabbix-web-mysql", "zabbix-frontend-php"),
])
def test_zabbix_package(host, server, redhat, debian):
    host = host.backend.get_hostname()
    host = host.replace("-centos7", "")
    host = host.replace("-centos8", "")
    host = host.replace("-debian", "")
    host = host.replace("-ubuntu", "")

    if host == server:
        if host.system_info.distribution in ['debian', 'ubuntu']:
            zabbix_web = host.package(debian)
            assert zabbix_web.version.startswith("1:5.4")
        elif host.system_info.distribution == 'centos':
            zabbix_web = host.package(redhat)
            assert zabbix_web.version.startswith("5.4")
        assert zabbix_web.is_installed


def test_zabbix_web(host):
    zabbix_web = host.file("/etc/zabbix/web/zabbix.conf.php")
    ansible_variables = host.ansible.get_variables()
    zabbix_websrv = str(ansible_variables['zabbix_websrv'])

    if host.system_info.distribution in ['debian', 'ubuntu']:
        assert zabbix_web.user == "www-data"
        assert zabbix_web.group == "www-data"
    elif host.system_info.distribution == 'centos':
        if zabbix_websrv == 'apache':
            assert zabbix_web.user == "apache"
            assert zabbix_web.group == "apache"
        elif zabbix_websrv == 'nginx':
            assert zabbix_web.user == "nginx"
            assert zabbix_web.group == "nginx"
    assert zabbix_web.mode == 0o640


def test_zabbix_api(host):
    my_host = host.ansible.get_variables()
    zabbix_api_server_url = str(my_host['zabbix_api_server_url'])
    hostname = 'http://' + zabbix_api_server_url + '/api_jsonrpc.php'
    post_data = '{"jsonrpc": "2.0", "method": "user.login", "params": { "user": "Admin", "password": "zabbix" }, "id": 1, "auth": null}'
    headers = 'Content-Type: application/json-rpc'
    command = "curl -XPOST -H '" + str(headers) + "' -d '" + str(post_data) + "' '" + hostname + "'"

    cmd = host.run(command)
    assert '"jsonrpc":"2.0","result":"' in cmd.stdout
