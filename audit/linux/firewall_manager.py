import os
import warnings
from audit.core.core import exec_command, shell_command, cd
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager
from audit.linux.script_builder import generate_scripts


class LinuxFirewallManager(FirewallManager):

    def __init__(self, path_scripts):
        super().__init__()
        generate_scripts(path_scripts)

    def firewall_descriptor(self):
        result = dict()
        result["status"] = self.is_compatible()
        result["data"] = [
            {
                "name": "add chain",
                "args": {
                    "name": "",
                },
                "show": False,
                "command": "firewall add rule"
            },
            {
                "name": "remove chain",
                "args": {
                    "name": ""
                },
                "show": False,
                "command": "firewall add rule"
            },
            {
                "name": "add rule",
                "args": {
                    "chain name": "",
                    "interface": "",
                    "src": "",
                    "action": "",
                    "protocol": "",
                },
                "show": False,
                "command": "firewall add rule"
            },
            {
                "name": "remove rule",
                "args": {
                    "name": "",
                },
                "show": False,
                "command": "firewall remove rule"
            },
            {
                "name": "view rules",
                "args": {},
                "show": True,
                "command": "firewall get rules"
            },
            {
                "name": "export settings",
                "args": {
                    "filename": ""
                },
                "show": True,
                "command": "firewall export"
            },
            {
                "name": "import settings",
                "args": {
                    "filename": ""
                },
                "show": True,
                "command": "firewall import"
            },
            {
                "name": "disable",
                "args": {},
                "show": True,
                "command": "firewall disable"
            },
            {
                "name": "enable",
                "args": {},
                "show": True,
                "command": "firewall enable"
            },
            {
                "name": "status",
                "args": {},
                "show": False,
                "command": "firewall status"
            },
            {
                "name": "files",
                "args": {},
                "show": False,
                "command": "firewall files"
            }
        ]
        result["fw_status"] = self.status()
        return result

    def add_chain(self, args):
        pass

    def remove_chain(self, args):
        pass

    def add_rule(self, args):
        pass

    def remove_rule(self, args):
        pass

    def get_rules(self):
        pass

    def export_firewall(self, args):
        filename = args["filename"]
        command = "iptables-save > " + Environment().path_firewall_resources + "/" + filename + ".rules"
        return exec_command(command)

    def import_firewall(self, args):
        filename = args["file"]
        command = "iptables-restore < " + Environment().path_firewall_resources + "/" + filename + ".rules"
        return exec_command(command)

    def disable(self):
        command = "iptables-save > " + Environment().path_firewall_resources + "/last.rules"
        shell_command(command)
        act_cwd = os.getcwd()
        cd(Environment().path_embedded_scripts)
        result = exec_command("./down_iptables.sh")
        cd(act_cwd)
        return result

    def enable(self):
        result = dict()
        command = "iptables-restore < " + Environment().path_firewall_resources + "/last.rules"
        command_result = exec_command(command)
        if command_result["status"]:
            data = exec_command("iptables --list-rules")
            result["status"] = self.parse_status(data["data"])["iptables"]
            result["data"] = command_result["data"]
        else:
            result["status"] = False
            result["data"] = ""
        return result

    def status(self):
        result = dict()
        data = exec_command("iptables --list-rules")
        if data["status"]:
            result["status"] = True
            result["data"] = self.parse_status(data["data"])
            result["administrator"] = True
        else:
            result["status"] = False
            result["administrator"] = False
            result["data"] = ""
        return result

    def parse_rules(self, string):
        pass

    def is_compatible(self):
        try:
            return exec_command('iptables -h')["status"]
        except Exception as e:
            warnings.warn(str(e))
            return False

    def parse_status(self, string):
        lines = string.split("\n")
        status_data = dict()
        status_data["iptables"] = not("-P INPUT ACCEPT" in lines and "-P FORWARD ACCEPT" in lines and "-P OUTPUT ACCEPT" in lines and len(lines) == 4)
        return status_data
