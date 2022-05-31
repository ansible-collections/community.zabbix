import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent")


def test_zabbix_agent_dot_conf(zabbix_agent_conf):
    assert zabbix_agent_conf.contains("TLSAccept=psk")
    assert zabbix_agent_conf.contains("TLSPSKIdentity=my_Identity")
    assert zabbix_agent_conf.contains("TLSPSKFile=/data/certs/zabbix.psk")


def test_zabbix_agent_psk(host):
    psk_file = host.file("/data/certs/zabbix.psk")
    assert psk_file.user == "zabbix"
    assert psk_file.group == "zabbix"
    assert psk_file.mode == 0o400
    assert psk_file.contains(
        "97defd6bd126d5ba7fa5f296595f82eac905d5eda270207a580ab7c0cb9e8eab"
    )
