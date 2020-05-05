import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('docker')


def test_docker_running(host):
    zabbixagent = host.docker("zabbix-agent")
    zabbixagent.is_running


def test_zabbix_include_dir(host):
    zabbixagent = host.file("/etc/zabbix/zabbix_agentd.d")
    assert zabbixagent.is_directory
    assert zabbixagent.user == "root"
    assert zabbixagent.group == "zabbix"


def test_socket(host):
    assert host.socket("tcp://0.0.0.0:10050").is_listening
