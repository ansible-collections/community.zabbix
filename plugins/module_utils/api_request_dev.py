import os
import json
import requests

class ZabbixApiNamespace:
    def __init__(self, parent, namespace):
        self._parent = parent
        self._namespace = namespace

    def __getattr__(self, method):
        def call(params=None):
            return self._parent.send({
                "method": f"{self._namespace}.{method}",
                "params": params or {}
            })
        return call


class ZabbixApiRequest:
    def __init__(self, module):
        self.module = module

        host = os.getenv("ZABBIX_HOST")
        port = os.getenv("ZABBIX_PORT", "443")
        use_ssl = os.getenv("ZABBIX_USE_SSL", "true").lower() == "true"
        self.auth = os.getenv("ZABBIX_AUTH_KEY")
        self.verify = os.getenv("ZABBIX_VALIDATE_CERTS", "true").lower() == "true"

        if not host or not self.auth:
            module.fail_json(msg="ZABBIX_HOST and ZABBIX_AUTH_KEY must be set in the environment.")

        proto = "https" if use_ssl else "http"
        self.url = f"{proto}://{host}:{port}/api_jsonrpc.php"
        self.headers = {"Content-Type": "application/json-rpc"}

    def send(self, data):
        data.setdefault("jsonrpc", "2.0")
        data.setdefault("id", 1)
        if "auth" not in data and data["method"] != "apiinfo.version":
            data["auth"] = self.auth

        try:
            response = requests.post(self.url, json=data, headers=self.headers, timeout=10, verify=self.verify)
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            self.module.fail_json(msg=f"Request to Zabbix API failed: {str(e)}")

        if "error" in result:
            self.module.fail_json(msg=f"Zabbix API error: {result['error']}")

        return result.get("result")

    def api_version(self):
        return self.send({
            "method": "apiinfo.version",
            "params": {}
        })

    def __getattr__(self, namespace):
        return ZabbixApiNamespace(self, namespace)