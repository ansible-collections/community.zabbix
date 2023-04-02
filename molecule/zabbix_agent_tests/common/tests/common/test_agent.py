import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent")


def test_zabbixagent_running_and_enabled(host, zabbix_agent_service):
    # Find out why this is not working for linuxmint and opensuse
    if host.system_info.distribution not in ["linuxmint", "opensuse", "ubuntu"]:
        assert zabbix_agent_service.is_running
        assert zabbix_agent_service.is_enabled


def test_zabbix_agent_dot_conf(zabbix_agent_conf):
    assert zabbix_agent_conf.user == "root"
    assert zabbix_agent_conf.group == "root"
    assert zabbix_agent_conf.mode == 0o644

    assert zabbix_agent_conf.contains("Server=192.168.3.33")
    assert zabbix_agent_conf.contains("ServerActive=192.168.3.33")
    assert zabbix_agent_conf.contains("DebugLevel=3")


def test_zabbix_include_dir(zabbix_agent_include_dir):
    assert zabbix_agent_include_dir.is_directory
    assert zabbix_agent_include_dir.user == "root"
    assert zabbix_agent_include_dir.group == "zabbix"


def test_socket(host):
    # Find out why this is not working for linuxmint and opensus
    if host.system_info.distribution not in ["linuxmint", "opensuse"]:
        assert host.socket("tcp://0.0.0.0:10050").is_listening


def test_zabbix_package(host, zabbix_agent_package):
    assert zabbix_agent_package.is_installed

    if host.system_info.distribution == "debian":
        if host.system_info.codename in ["bullseye", "focal"]:
            assert zabbix_agent_package.version.startswith("1:6.4")
        else:
            assert zabbix_agent_package.version.startswith("1:6.0")
    if host.system_info.distribution == "centos":
        assert zabbix_agent_package.version.startswith("6.4")
