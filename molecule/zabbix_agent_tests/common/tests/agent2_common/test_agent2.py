import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent2")


def test_zabbix_agent2_dot_conf(host, zabbix_agent_file):
    assert zabbix_agent_file.contains("Plugins.SystemRun.LogRemoteCommands=0")
