import pytest
import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("agent")


def test_zabbix_agent_dot_conf(host, zabbix_agent_conf):
    assert zabbix_agent_conf.contains("TLSAccept=psk")
    assert zabbix_agent_conf.contains(
        f"TLSPSKIdentity={host.ansible.get_variables()['inventory_hostname']}"
    )
    assert zabbix_agent_conf.contains("TLSPSKFile=/etc/zabbix/tls_psk_auto.secret")


def test_zabbix_agent_autopsk(host):
    psk_file = host.file("/etc/zabbix/tls_psk_auto.secret")
    assert psk_file.user == "zabbix"
    assert psk_file.group == "zabbix"
    assert psk_file.mode == 0o400
    assert psk_file.size == 64
