import warnings
from audit.core.core import exec_command, shell_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager


class LinuxFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

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
        print(result)
        return result

    def add_chain(self, args):
        import iptc
        result = dict()
        result["status"] = True
        result["data"] = ""
        name = args["name"]
        iptc.Table.FILTER.create_chain(name)
        return result

    def remove_chain(self, args):
        import iptc
        result = dict()
        result["status"] = True
        result["data"] = ""
        name = args["name"]
        iptc.Table.FILTER.delete_chain(name)
        return result

    def add_rule(self, args):
        import iptc
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
        import iptc
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
        import iptc
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
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/" + filename + ".rules\""
        return exec_command(command)

    def import_firewall(self, args):
        filename = args["file"]
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/" + filename + ".rules\""
        return exec_command(command)

    def disable(self):
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/last.rules\""
        shell_command(command)
        return exec_command("./" + Environment().path_embedded_scripts + "/down_iptables.sh")

    def enable(self):
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/last\""
        return exec_command(command)

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
            import iptc
            return True
        except Exception as e:
            warnings.warn(str(e))
            return False

    def parse_status(self, string):
        lines = string.split("\n")
        status_data = dict()
        status_data["iptables"] = "-P INPUT ACCEPT" in lines and "-P FORWARD ACCEPT" in lines and "-P OUTPUT ACCEPT" in lines and len(lines) == 3
        return status_data
