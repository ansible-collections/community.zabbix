import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


def test_zabbix_package(host):
    ansible_data = host.ansible.get_variables()
    version = ansible_data['zabbix_web_version']
    webserver = ansible_data['zabbix_web_http_server']

    package_name = f'zabbix-{webserver}-conf'
    if host.system_info.distribution == "opensuse-leap" and version == 7.0:
        package_name = f'zabbix-{webserver}-conf-php8'
    
    zabbix_web = host.package(package_name)
    assert str(version) in zabbix_web.version


def test_zabbix_web(host):
    zabbix_web = host.file("/etc/zabbix/web/zabbix.conf.php")
    ansible_variables = host.ansible.get_variables()
    zabbix_websrv = str(ansible_variables["zabbix_web_http_server"])

    if host.system_info.distribution in ["debian", "ubuntu"]:
        assert zabbix_web.user == "www-data"
        assert zabbix_web.group == "www-data"
    elif host.system_info.distribution == "centos":
        if zabbix_websrv == "apache":
            assert zabbix_web.user == "apache"
            assert zabbix_web.group == "apache"
        elif zabbix_websrv == "nginx":
            assert zabbix_web.user == "nginx"
            assert zabbix_web.group == "nginx"
    elif host.system_info.distribution == "opensuse-leap":
        if zabbix_websrv == "apache":
            assert zabbix_web.user == "wwwrun"
            assert zabbix_web.group == "wwwrun"
        elif zabbix_websrv == "nginx":
            assert zabbix_web.user == "nginx"
            assert zabbix_web.group == "nginx"
    assert zabbix_web.mode == 0o644


def test_zabbix_api(host):
    my_host = host.ansible.get_variables()
    zabbix_api_server_url = str(my_host["zabbix_api_server_url"])
    hostname = "http://" + zabbix_api_server_url + "/api_jsonrpc.php"
    post_data = '{"jsonrpc": "2.0", "method": "user.login", "params": { "username": "Admin", "password": "zabbix" }, "id": 1, "auth": null}'
    headers = "Content-Type: application/json-rpc"
    command = (
        "curl -XPOST -H '"
        + str(headers)
        + "' -d '"
        + str(post_data)
        + "' '"
        + hostname
        + "'"
    )

    cmd = host.run(command)
    assert '"jsonrpc":"2.0","result":"' in cmd.stdout
