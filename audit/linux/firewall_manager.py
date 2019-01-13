import datetime
import iptc
from audit.core.core import exec_command, shell_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager


class LinuxFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

    def firewall_descriptor(self):
        result = dict()
        result["status"] = True
        result["data"] = [
            {
                "name": "add chain",
                "args": {
                    "name": "",
                }
            },
            {
                "name": "remove chain",
                "args": {
                    "name": ""
                }
            },
            {
                "name": "add rule",
                "args": {
                    "chain name": "",
                    "interface": "",
                    "src": "",
                    "action": "",
                    "protocol": "",
                }
            },
            {
                "name": "remove rule",
                "args": {
                    "name": "",
                }
            },
            {
                "name": "get rules",
                "args": {}
            },
            {
                "name": "export settings",
                "args": {}
            },
            {
                "name": "import settings",
                "args": {
                    "file": ""
                }
            },
            {
                "name": "disable",
                "args": {}
            },
            {
                "name": "enable",
                "args": {}
            }
        ]
        return result

    def add_chain(self, args):
        result = dict()
        result["status"] = True
        result["data"] = ""
        name = args["name"]
        iptc.Table.FILTER.create_chain(name)
        return result

    def remove_chain(self, args):
        result = dict()
        result["status"] = True
        result["data"] = ""
        name = args["name"]
        iptc.Table.FILTER.delete_chain(name)
        return result

    def add_rule(self, args):
        result = dict()
        result["status"] = True
        result["data"] = ""
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), args["chain_name"])
        rule = iptc.Rule()
        kwargs = {name: value for name, value in args.items() if value != ""}
        if kwargs.get("interface") is not None: rule.in_interface = kwargs.get("interface")
        if kwargs.get("src") is not None: rule.src = kwargs.get("src")
        if kwargs.get("action") is not None: rule.create_target(kwargs.get("action"))
        if kwargs.get("protocol") is not None: rule.protocol = kwargs.get("protocol")
        chain.insert_rule(rule)
        return result

    def remove_rule(self, args):
        result = dict()
        result["status"] = False
        result["data"] = "rule named " + args["name"] + " not found"
        rule_name = args["name"]
        table = iptc.Table(iptc.Table.FILTER)
        table.autocommit = False
        for chain in table.chains:
            for rule in chain.rules:
                if rule.target.name == rule_name:
                    chain.delete_rule(rule)
                    result["status"] = True
                    result["data"] = "remove successfully"
        table.commit()
        table.autocommit = True

    def get_rules(self):
        result = dict()
        result["status"] = True
        result_str = ""
        table = iptc.Table(iptc.Table.ALL)
        for chain in table.chains:
            result_str += "Chain " + chain.name
            for rule in chain.rules:
                result_str += "Rule " + rule.target.name + "\n     proto: " + rule.protocol + "\n     src: " + rule.src, "\n     dst: " + \
                              rule.dst + "\n     in: " + rule.in_interface + "\n     out: " + rule.out_interface
        result["data"] = result_str
        return result

    def export_firewall(self, args):
        filename = args["filename"]
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/" + filename + "\""
        return exec_command(command)

    def import_firewall(self, args):
        filename = args["file"]
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/" + filename + "\""
        return exec_command(command)

    def disable(self):
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/last\""
        shell_command(command)
        shell_command("iptables -X")
        shell_command("iptables -t nat -F")
        shell_command("iptables -t nat -X")
        shell_command("iptables -t mangle -F")
        shell_command("iptables -t mangle -X")
        shell_command("iptables -P INPUT ACCEPT")
        shell_command("iptables -P FORWARD ACCEPT")
        return exec_command("iptables -P OUTPUT ACCEPT")

    def enable(self):
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/last\""
        return exec_command(command)

    def status(self):
        pass

    def parse_rules(self, string):
        pass
