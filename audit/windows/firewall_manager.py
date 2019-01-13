from audit.core.core import exec_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager, Rule


class WindowsFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

    def firewall_descriptor(self):
        result = dict()
        result["status"] = True
        result["data"] = [
            {
                "name": "add rule",
                "args": {
                    "name": "",
                    "interface": "",
                    "action": "",
                    "protocol": "",
                    "local port": "",
                    "program": "",
                }
            },
            {
                "name": "remove rule",
                "args": {
                    "name": ""
                }
            },
            {
                "name": "get rules",
                "args": {}
            },
            {
                "name": "export setting",
                "args": {
                    "filename": ""
                }
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
        pass

    def remove_chain(self, args):
        pass

    def add_rule(self, args):
        command = ""
        for key, value in args.items():
            command += " " + key + "=" + value
        return exec_command(command)

    def remove_rule(self, args):
        name = args["name"]
        command = "netsh advfirewall firewall delete rule name=" + name
        return exec_command(command)

    def get_rules(self):
        result = dict()
        command = "netsh advfirewall firewall show rule name=all"
        data = exec_command(command)
        if data["status"]:
            result["status"] = True
            self.rules = self.parse_rules(data["data"])
            result["data"] = Rule.list_to_json(self.rules)
        else:
            result["status"] = False
        return result

    def export_firewall(self, args):
        filename = args["filename"] + ".wfw"
        command = "netsh advfirewall export \"" + Environment().path_firewall_resources + "/" + filename + "\""
        print(command)
        return exec_command(command)

    def import_firewall(self, args):
        filename = args["file"]
        command = "netsh advfirewall import \"" + Environment().path_firewall_resources + "/" + filename + "\""
        exec_command(command)

    def disable(self):
        return exec_command("netsh advfirewall set allprofiles state off")

    def enable(self):
        return exec_command("netsh advfirewall set allprofiles state on")

    def status(self):
        result = dict()
        data = exec_command("netsh Advfirewall show all state")
        if data["status"]:
            result["status"] = True
            result["data"] = self.parse_status(data["data"])
        else:
            result["status"] = False
        return result

    def parse_rules(self, string):
        rules = []
        lines = string.split('\n')
        is_rule = False
        actual_rule_num = 0
        actual_rule_args = dict()
        for line in lines:
            if line.replace(" ", "") != '':
                if line.startswith('-'):
                    pass
                else:
                    is_rule = True
                    attr = line.split(':')
                    if len(attr) > 1:
                        attr_name = attr[0].strip()
                        attr_value = attr[1].strip()
                        actual_rule_args[attr_name] = attr_value
            elif is_rule:
                is_rule = False
                rules.append(Rule(number=actual_rule_num, kwargs=actual_rule_args))
                actual_rule_num = actual_rule_num + 1
                actual_rule_args = dict()
        return rules

    def parse_status(self, string):
        lines = string.split("\n")
        cursor = 1
        status_data = dict()

        status_domain_name = lines[cursor].strip()
        cursor += 2
        status_domain = lines[cursor].split()[1]
        status_data[status_domain_name] = status_domain
        cursor += 2

        status_public_name = lines[cursor].strip()
        cursor += 2
        status_public = lines[cursor].split()[1]
        status_data[status_public_name] = status_public
        cursor += 2

        status_private_name = lines[cursor].strip()
        cursor += 2
        status_private = lines[cursor].split()[1]
        status_data[status_private_name] = status_private
        cursor += 2

        return status_data
