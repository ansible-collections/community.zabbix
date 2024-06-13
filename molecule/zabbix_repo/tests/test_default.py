import os
import pytest
from pathlib import Path


import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


def test_zabbix_manage_repo_installed(host):
    os = host.system_info.distribution
    if os in ["rocky"]:
        result = host.ansible("command", "yum update -y", check=False, become=True)["rc"]
    elif os in ["debian", "ubuntu"]:
        result = host.ansible("command", "apt update", check=False, become=True)["rc"]
    elif os in ["opensuse-leap"]:
        result = host.ansible("command", "zypper refresh", check=False, become=True)["rc"]
    assert result == 0
