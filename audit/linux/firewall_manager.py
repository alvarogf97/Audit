import os
import warnings
from audit.core.core import exec_command, shell_command, cd
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager, Rule
from audit.linux.script_builder import generate_scripts


class LinuxFirewallManager(FirewallManager):

    parameters = {"chain name": "", "origin": "-s", "port": "--dport", "protocol": "-p", "policy": "-j"}

    def __init__(self, path_scripts):
        super().__init__()
        generate_scripts(path_scripts)

    def execute_firewall_action(self, command: str, args):
        if command.startswith("firewall add rule"):
            return self.add_rule(args)
        elif command.startswith("firewall remove rule"):
            return self.remove_rule(args)
        elif command.startswith("firewall get rules"):
            return self.get_rules()
        elif command.startswith("firewall export"):
            return self.export_firewall(args)
        elif command.startswith("firewall import"):
            return self.import_firewall(args)
        elif command.startswith("firewall disable"):
            return self.disable()
        elif command.startswith("firewall enable"):
            return self.enable()
        elif command.startswith("firewall descriptor"):
            return self.firewall_descriptor()
        elif command.startswith("firewall add chain"):
            return LinuxFirewallManager.add_chain(args)
        elif command.startswith("firewall remove chain"):
            return self.remove_chain(args)
        elif command.startswith("firewall status"):
            return self.status()
        elif command.startswith("firewall files"):
            return self.get_firewall_files()
        elif command.startswith("firewall get chains"):
            return LinuxFirewallManager.get_chains()
        elif command.startswith("firewall change chain policy"):
            return self.change_chain_policy(args)
        elif command.startswith("firewall flush chain"):
            return self.flush_chain(args)
        else:
            result = dict()
            result["status"] = False
            result["data"] = "unavailable operation"
            return result

    def firewall_descriptor(self):
        result = dict()
        result["status"] = self.is_compatible()
        result["data"] = [
            {
                "name": "view chains",
                "args": {},
                "show": True,
                "command": "firewall get chains"
            },
            {
                "name": "flush chain",
                "args": {
                    "name": ""
                },
                "show": False,
                "command": "firewall flush chain"
            },
            {
                "name": "policy chain",
                "args": {
                    "name": "",
                    "policy": ""
                },
                "show": False,
                "command": "firewall change chain policy"
            },
            {
                "name": "add chain",
                "args": {
                    "name": "",
                },
                "show": False,
                "command": "firewall add chain"
            },
            {
                "name": "remove chain",
                "args": {
                    "name": ""
                },
                "show": False,
                "command": "firewall remove chain"
            },
            {
                "name": "add rule",
                "args": {
                    "chain name": "",
                    "origin": "",
                    "port": "",
                    "protocol": "",
                    "policy": "",
                },
                "show": False,
                "command": "firewall add rule"
            },
            {
                "name": "remove rule",
                "args": {
                    "number": "",
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

    @staticmethod
    def get_chains():
        result = dict()
        data = exec_command("iptables -L")
        if data["status"]:
            result["status"] = True
            result["data"] = Chain.list_to_json(LinuxFirewallManager.parse_chain(data["data"]))
        else:
            result["status"] = False
            result["data"] = []
        return result

    @staticmethod
    def add_chain(args):
        name = args["name"]
        return exec_command("iptables -N " + name)

    @staticmethod
    def remove_chain(args):
        name = args["name"]
        return exec_command("iptables -X " + name)

    @staticmethod
    def change_chain_policy(args):
        name = args["name"]
        policy = args["policy"]
        return exec_command("iptables -P " + name + " " + policy)

    @staticmethod
    def flush_chain(args):
        name = args["name"]
        return exec_command("iptables -F " + name)

    def add_rule(self, args):
        info = ""
        for name_arg, value in args.items():
            if value != "":
                info += self.parameters[name_arg] + " " + value + " "
        return exec_command("iptables -A" + info)

    def remove_rule(self, args):
        rule = self.rules[args["number"]]
        name = rule.name
        command = "iptables -D " + name
        return exec_command(command)

    def get_rules(self):
        result = dict()
        command = "iptables -S"
        data = exec_command(command)
        if data["status"]:
            result["status"] = True
            self.rules = self.parse_rules(data["data"])
            result["data"] = Rule.list_to_json(self.rules)
        else:
            result["status"] = False
        return result

    def export_firewall(self, args):
        filename = args["filename"]
        command = "iptables-save > " + Environment().path_firewall_resources + "/" + filename + ".rules"
        return exec_command(command)

    def import_firewall(self, args):
        filename = args["filename"]
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
        rules = []
        rule_number = 0
        lines = string.split("\n")
        for line in lines:
            if line.startswith("-A"):
                token_line = line.split(" ")
                name = " ".join(token_line[1:])
                rule = Rule(number=rule_number, name=name, kwargs=dict())
                rules.append(rule)
        return rules

    def is_compatible(self):
        try:
            return exec_command('iptables -h')["status"]
        except Exception as e:
            warnings.warn(str(e))
            return False

    def parse_status(self, string):
        lines = string.split("\n")
        status_data = dict()
        status_data["iptables"] = not("-P INPUT ACCEPT" in lines and "-P FORWARD ACCEPT" in lines
                                      and "-P OUTPUT ACCEPT" in lines and len(lines) == 4)
        return status_data

    @staticmethod
    def parse_chain(string):
        lines = string.split("\n")
        chain_list = []
        for line in lines:
            if line.startswith("Chain"):
                token_line = line.replace("(", "").replace(")", "").split(" ")
                name = token_line[1]
                if token_line[3] == 'references':
                    policy = "CUSTOM"
                else:
                    policy = token_line[3]
                chain = Chain(name=name, policy=policy)
                chain_list.append(chain)
        return chain_list


class Chain:

    default_chains = ["INPUT", "OUTPUT", "FORWARD"]

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy
        self.is_removable = name not in self.default_chains

    def to_json(self):
        result = dict()
        result["name"] = self.name
        result["policy"] = self.policy
        result["is_removable"] = self.is_removable
        return result

    @staticmethod
    def list_to_json(chain_list):
        result = []
        for chain in chain_list:
            result.append(chain.to_json())
        return result
