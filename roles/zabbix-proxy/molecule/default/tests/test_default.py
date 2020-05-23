import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_zabbixproxy_running_and_enabled(Service, SystemInfo):
    zabbix = Service("zabbix-proxy")
    # assert zabbix.is_enabled
    if SystemInfo.distribution not in ['ubuntu']:
        assert zabbix.is_running


@pytest.mark.parametrize("proxy", [
    ("zabbix-proxy-pgsql"),
    ("zabbix-proxy-mysql"),
])
def test_zabbix_package(Package, TestinfraBackend, proxy, SystemInfo):
    host = TestinfraBackend.get_hostname()
    host = host.replace("-centos", "")
    host = host.replace("-debian", "")

    if host == proxy:
        zabbix_proxy = Package(proxy)
        assert zabbix_proxy.is_installed

        if SystemInfo.distribution in ['debian', 'ubuntu']:
            assert zabbix_proxy.version.startswith("1:4.4")
        elif SystemInfo.distribution == 'centos':
            assert zabbix_proxy.version.startswith("4.4")


def test_socket(Socket):
    assert Socket("tcp://0.0.0.0:10051").is_listening


def test_zabbix_proxy_dot_conf(File):
    zabbix_proxy_conf = File("/etc/zabbix/zabbix_proxy.conf")
    assert zabbix_proxy_conf.user == "zabbix"
    assert zabbix_proxy_conf.group == "zabbix"
    assert zabbix_proxy_conf.mode == 0o644

    assert zabbix_proxy_conf.contains("ListenPort=10051")
    assert zabbix_proxy_conf.contains("DBHost=localhost")
    assert zabbix_proxy_conf.contains("DebugLevel=3")


def test_zabbix_include_dir(File):
    zabbix_include_dir = File("/etc/zabbix/zabbix_proxy.conf.d")
    assert zabbix_include_dir.is_directory
    assert zabbix_include_dir.user == "zabbix"
    assert zabbix_include_dir.group == "zabbix"
    assert zabbix_include_dir.mode == 0o755
