import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('agent')


def test_zabbixagent_running_and_enabled(host):
    zabbixagent = host.service("zabbix-agent")
    # Find out why this is not working for linuxmint and opensuse
    if host.system_info.distribution not in ['linuxmint', 'opensuse', 'ubuntu']:
        assert zabbixagent.is_running
        assert zabbixagent.is_enabled


def test_zabbix_agent_dot_conf(host):
    if host.system_info.distribution in ['opensuse']:
        passwd = host.file("/etc/zabbix/zabbix-agentd.conf")
    else:
        passwd = host.file("/etc/zabbix/zabbix_agentd.conf")
    assert passwd.user == "root"
    assert passwd.group == "root"
    assert passwd.mode == 0o644

    assert passwd.contains("Server=192.168.3.33")
    assert passwd.contains("ServerActive=192.168.3.33")
    assert passwd.contains("DebugLevel=3")
    assert passwd.contains("TLSAccept=psk")
    assert passwd.contains("TLSPSKIdentity=my_Identity")
    assert passwd.contains("TLSPSKFile=/data/certs/zabbix.psk")


def test_zabbix_agent_psk(host):
    psk_file = host.file("/data/certs/zabbix.psk")
    assert psk_file.user == "zabbix"
    assert psk_file.group == "zabbix"
    assert psk_file.mode == 0o400
    assert psk_file.contains("97defd6bd126d5ba7fa5f296595f82eac905d5eda270207a580ab7c0cb9e8eab")


def test_zabbix_include_dir(host):
    zabbixagent = host.file("/etc/zabbix/zabbix_agentd.d")
    assert zabbixagent.is_directory
    assert zabbixagent.user == "root"
    assert zabbixagent.group == "zabbix"


def test_socket(host):
    # Find out why this is not working for linuxmint and opensus
    if host.system_info.distribution not in ['linuxmint', 'opensuse']:
        assert host.socket("tcp://0.0.0.0:10050").is_listening


@pytest.mark.parametrize("zabbix_packages", [
    ("zabbix-agent"),
])
def test_zabbix_package(host, zabbix_packages):
    zabbixagent = host.package(zabbix_packages)
    assert zabbixagent.is_installed

    if host.system_info.distribution == 'debian':
        assert zabbixagent.version.startswith("1:5.4")
    if host.system_info.distribution == 'centos':
        assert zabbixagent.version.startswith("5.4")
