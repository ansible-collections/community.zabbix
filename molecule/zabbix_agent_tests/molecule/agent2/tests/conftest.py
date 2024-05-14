import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent")


@pytest.fixture
def zabbix_agent_conf(host):
    if host.system_info.distribution in ["opensuse"]:
        passwd = host.file("/etc/zabbix/zabbix-agentd.conf")
    else:
        passwd = host.file("/etc/zabbix/zabbix_agent2.conf")

    return passwd


@pytest.fixture
def zabbix_agent_service(host):
    return host.service("zabbix-agent2")


@pytest.fixture
def zabbix_agent_include_dir(host):
    return host.file("/etc/zabbix/zabbix_agent2.d")


@pytest.fixture
def zabbix_agent_package(host):
    return host.package("zabbix-agent2")
