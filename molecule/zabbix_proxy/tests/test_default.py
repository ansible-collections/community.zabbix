import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


def test_zabbixproxy_running_and_enabled(host):
    zabbix = host.service("zabbix-proxy")
    if host.system_info.distribution == "centos":
        assert zabbix.is_enabled
        assert zabbix.is_running
    else:
        assert zabbix.is_running


@pytest.mark.parametrize(
    "proxy", [("zabbix-proxy-pgsql"), ("zabbix-proxy-mysql"), ("zabbix-proxy-sqlite3")]
)
def test_zabbix_package(host, proxy):
    ansible_data = host.ansible.get_variables()
    zabbixhost = ansible_data["inventory_hostname"]

    zabbixhost = zabbixhost.replace("-centos", "")
    zabbixhost = zabbixhost.replace("-debian", "")
    zabbixhost = zabbixhost.replace("-ubuntu", "")

    if zabbixhost == proxy:
        zabbix_proxy = host.package(proxy)
        if host.system_info.distribution in ["debian", "ubuntu"]:
            assert zabbix_proxy.version.startswith("1:6.4")
        elif host.system_info.distribution == "centos":
            assert zabbix_proxy.version.startswith("6.4")
        assert zabbix_proxy.is_installed


def test_zabbix_proxy_dot_conf(host):
    found = False
    for file_name in [
        "/etc/zabbix/zabbix_proxy.conf",
        "/etc/zabbix_proxy.conf",
    ]:
        if host.file(file_name).exists:
            found = True
            break

    assert found
    zabbix_proxy_conf = host.file(file_name)
    assert zabbix_proxy_conf.user in ["zabbix", "zabbixsrv"]
    assert zabbix_proxy_conf.group in ["zabbix", "zabbixsrv"]
    assert zabbix_proxy_conf.mode == 0o644

    assert zabbix_proxy_conf.contains("ListenPort=10051")
    assert zabbix_proxy_conf.contains("DebugLevel=3")


def test_zabbix_include_dir(host):
    zabbix_include_dir = host.file("/etc/zabbix/zabbix_proxy.conf.d")
    assert zabbix_include_dir.is_directory
    assert zabbix_include_dir.user in ["zabbix", "zabbixsrv"]
    assert zabbix_include_dir.group in ["zabbix", "zabbixsrv"]
    # assert zabbix_include_dir.mode == 0o644


def test_zabbix_proxy_logfile(host):
    found = False
    for file_name in [
        "/var/log/zabbix/zabbix_proxy.log",
        "/var/log/zabbixsrv/zabbix_proxy.log",
    ]:
        if host.file(file_name).exists:
            found = True
            break

    assert found

    zabbix_logfile = host.file(file_name)
    assert not zabbix_logfile.contains("Access denied for user")
    assert not zabbix_logfile.contains("database is down: reconnecting")
    assert zabbix_logfile.contains("current database version")
    assert zabbix_logfile.contains(r"proxy #0 started \[main process\]")
