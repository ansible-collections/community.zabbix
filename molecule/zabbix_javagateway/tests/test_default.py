import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_zabbix_running_and_enabled(host):
    zabbix = host.service("zabbix-java-gateway")
    assert zabbix.is_running


def test_zabbix_java_gateway_dot_conf(host):
    zabbix_proxy_conf = host.file("/etc/zabbix/zabbix_java_gateway.conf")
    assert zabbix_proxy_conf.user == "zabbix"
    assert zabbix_proxy_conf.group == "zabbix"
    assert zabbix_proxy_conf.mode == 0o644

    assert zabbix_proxy_conf.contains("LISTEN_IP=0.0.0.0")
    assert zabbix_proxy_conf.contains("LISTEN_PORT=10052")
    assert zabbix_proxy_conf.contains("PID_FILE=/run/zabbix/zabbix_java_gateway.pid")
    assert zabbix_proxy_conf.contains("START_POLLERS=5")
