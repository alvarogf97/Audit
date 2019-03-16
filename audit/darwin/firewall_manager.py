from audit.core.core import exec_command
from audit.core.firewall_manager import FirewallManager


class DarwinFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

    def execute_firewall_action(self, command: str, args):
        if command.startswith("firewall disable"):
            return self.disable()
        elif command.startswith("firewall enable"):
            return self.enable()
        elif command.startswith("firewall descriptor"):
            return self.firewall_descriptor()
        elif command.startswith("firewall status"):
            return self.status()
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
        pass

    def import_firewall(self, args):
        pass

    def disable(self):
        result = dict()
        exec_result = exec_command("pfctl -d")
        result["data"] = exec_result["data"]
        result["status"] = not self.status()["data"]["pfctl"]
        return result

    def enable(self):
        result = dict()
        exec_result = exec_command("pfctl -e")
        result["data"] = exec_result["data"]
        result["status"] = self.status()["data"]["pfctl"]
        return result

    def status(self):
        result = dict()
        data = exec_command("pfctl -s info")
        if data["status"]:
            result["status"] = True
            result["data"] = self.parse_status(data["data"])
            result["administrator"] = True
        else:
            result["status"] = False
            result["administrator"] = False
            result["data"] = ""
        return result

    def parse_status(self, string):
        lines = string.split("\n")
        status_data = dict()
        status_data["pfctl"] = not "Disable" in lines[0]
        return status_data

    def parse_rules(self, string):
        pass

    def is_compatible(self):
        return exec_command("pfctl -s info")["status"]
