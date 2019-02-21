from audit.core.core import exec_command, restart
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager, Rule


class WindowsFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

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
        elif command.startswith("firewall status"):
            return self.status()
        elif command.startswith("firewall files"):
            return self.get_firewall_files()
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
                "name": "add rule",
                "args": {
                    "name": "",
                    "interface": "",
                    "action": "",
                    "protocol": "",
                    "localport": "",
                    "program": "",
                    "dir": ""
                },
                "show": False,
                "command": "firewall add rule"
            },
            {
                "name": "remove rule",
                "args": {
                    "number": ""
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

    def add_rule(self, args):
        result = dict()
        command = "netsh advfirewall firewall add rule"
        for key, value in args.items():
            if value != "":
                command += " " + key + "=" + value
        result["data"] = exec_command(command)["data"]
        result["status"] = len(result["data"]) < 13
        return result

    def remove_rule(self, args):
        result = dict()
        rule = self.rules[args["number"]]
        name = rule.name
        command = "netsh advfirewall firewall delete rule name=\"" + name + "\""
        result["data"] = exec_command(command)["data"]
        result["status"] = len(result["data"]) < 40
        return result

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
        result = dict()
        filename = args["filename"] + ".wfw"
        command = "netsh advfirewall export \"" + Environment().path_firewall_resources + "/" + filename + "\""
        result["data"] = exec_command(command)["data"]
        result["status"] = self.check_file(filename)
        return result

    def import_firewall(self, args):
        result = dict()
        filename = args["filename"]
        command = "netsh advfirewall import \"" + Environment().path_firewall_resources + "/" + filename + "\""
        result["data"] = exec_command(command)["data"]
        result["status"] = len(result["data"]) < 12
        if result["status"]:
            restart()
        return result

    def disable(self):
        result = dict()
        result["data"] = exec_command("netsh advfirewall set allprofiles state off")["data"]
        result["status"] = not self.check_status()
        return result

    def enable(self):
        result = dict()
        result["data"] = exec_command("netsh advfirewall set allprofiles state on")["data"]
        result["status"] = self.check_status()
        return result

    def status(self):
        result = dict()
        data = exec_command("netsh Advfirewall show all state")
        if data["status"]:
            result["status"] = True
            result["data"] = self.parse_status(data["data"])
        else:
            result["status"] = False
        result["administrator"] = exec_command("net session")["status"]
        return result

    def is_compatible(self):
        return True

    def parse_rules(self, string):
        rules = []
        lines = string.split('\n')
        is_rule = False
        actual_rule_name = ""
        actual_rule_num = 0
        actual_rule_args = dict()
        for line in lines:
            if len(line.replace(" ", "")) > 1:
                if line.startswith('-'):
                    pass
                else:
                    is_rule = True
                    attr = line.split(':')
                    if len(attr) > 1:
                        attr_name = attr[0].strip()
                        attr_value = attr[1].strip()
                        if actual_rule_name == "":
                            actual_rule_name = attr_value
                        else:
                            actual_rule_args[attr_name] = attr_value
            elif is_rule:
                is_rule = False
                rules.append(Rule(number=actual_rule_num, name=actual_rule_name, kwargs=actual_rule_args))
                actual_rule_num = actual_rule_num + 1
                actual_rule_name = ""
                actual_rule_args = dict()
        return rules

    def parse_status(self, string):
        lines = string.split("\n")
        cursor = 1
        status_data = dict()

        cursor += 2
        status_domain = lines[cursor].split()[1]
        status_data["domain"] = True if status_domain.lower().startswith("a") else False
        cursor += 2

        cursor += 2
        status_public = lines[cursor].split()[1]
        status_data["public"] = True if status_public.lower().startswith("a") else False
        cursor += 2

        cursor += 2
        status_private = lines[cursor].split()[1]
        status_data["private"] = True if status_private.lower().startswith("a") else False
        cursor += 2

        return status_data

    def check_status(self):
        result = True
        response = self.status()["data"]
        for key in response.keys():
            result = result and response.get(key)
        return result
