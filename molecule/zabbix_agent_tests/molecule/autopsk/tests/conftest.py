import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent")


@pytest.fixture
def zabbix_agent_conf(host):
    return host.file("/etc/zabbix/zabbix_agentd.conf")


@pytest.fixture
def zabbix_agent_service(host):
    return host.service("zabbix-agent")


@pytest.fixture
def zabbix_agent_include_dir(host):
    return host.file("/etc/zabbix/zabbix_agentd.d")


@pytest.fixture
def zabbix_agent_package(host):
    return host.package("zabbix-agent")
