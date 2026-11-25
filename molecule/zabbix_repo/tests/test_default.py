import os
import pytest
from configparser import ConfigParser
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


def test_managed_epel(host):
    facts = host.ansible("setup", "filter=ansible_os_family")["ansible_facts"]
    if facts["ansible_os_family"] != "RedHat":
        pytest.skip("EPEL management applies only to Red Hat family systems")

    assert host.package("epel-release").is_installed
    repo = ConfigParser()
    repo.read_string(host.file("/etc/yum.repos.d/epel.repo").content_string)
    assert repo.getboolean("epel", "enabled")
    assert "zabbix*" in repo.get("epel", "excludepkgs").split()
