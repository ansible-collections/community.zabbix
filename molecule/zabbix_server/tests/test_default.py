import os
import pytest
from pathlib import Path


import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


def test_zabbiserver_running_and_enabled(host):
    zabbix = host.service("zabbix-server")
    if host.system_info.distribution == "centos":
        assert zabbix.is_enabled
        assert zabbix.is_running
    else:
        assert zabbix.is_running


@pytest.mark.parametrize("server", [("zabbix-server-pgsql"), ("zabbix-server-mysql")])
def test_zabbix_package(host, server):
    ansible_data = host.ansible.get_variables()
    zabbixhost = ansible_data["inventory_hostname"]

    zabbixhost = zabbixhost.replace("-centos", "")
    zabbixhost = zabbixhost.replace("-debian", "")
    zabbixhost = zabbixhost.replace("-ubuntu", "")

    if zabbixhost == server:
        zabbix_server = host.package(server)
        if host.system_info.distribution in ["debian", "ubuntu"]:
            assert zabbix_server.version.startswith("1:6.4")
        elif host.system_info.distribution == "centos":
            assert zabbix_server.version.startswith("6.4")
        assert zabbix_server.is_installed


def test_zabbix_server_dot_conf(host):
    found = False
    for file_name in [
        "/etc/zabbix/zabbix_server.conf",
        "/etc/zabbix_server.conf",
    ]:
        if host.file(file_name).exists:
            found = True
            break

    assert found
    zabbix_server_conf = host.file(file_name)
    assert zabbix_server_conf.user in ["zabbix", "zabbixsrv"]
    assert zabbix_server_conf.group in ["zabbix", "zabbixsrv"]
    assert zabbix_server_conf.mode == 0o640

    assert zabbix_server_conf.contains("ListenPort=10051")
    assert zabbix_server_conf.contains("DebugLevel=3")


def test_zabbix_include_dir(host):
    zabbix_include_dir = host.file("/etc/zabbix/zabbix_server.conf.d")
    assert zabbix_include_dir.is_directory
    assert zabbix_include_dir.user in ["zabbix", "zabbixsrv"]
    assert zabbix_include_dir.group in ["zabbix", "zabbixsrv"]
    # assert zabbix_include_dir.mode == 0o644


def test_zabbix_server_logfile(host):
    found = False
    for file_name in [
        "/var/log/zabbix/zabbix_server.log",
        "/var/log/zabbixsrv/zabbix_server.log",
    ]:
        if host.file(file_name).exists:
            found = True
            break

    assert found

    zabbix_logfile = host.file(file_name)
    assert not zabbix_logfile.contains("Access denied for user")
    assert not zabbix_logfile.contains("database is down: reconnecting")
    assert zabbix_logfile.contains("current database version")
    assert zabbix_logfile.contains(r"server #0 started \[main process\]")
