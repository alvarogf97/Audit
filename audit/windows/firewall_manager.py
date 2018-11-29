import datetime
from audit.core.core import exec_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager


class WindowsFirewallManager(FirewallManager):

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
        command = "netsh advfirewall firewall show rule name=all"
        return exec_command(command)

    def export_firewall(self):
        time_info = datetime.datetime.now()
        filename = str(time_info.year) + "_" + str(time_info.month) + "_" \
                   + str(time_info.day) + "_" + str(time_info.hour) + "_" \
                   + str(time_info.minute) + ".wfw"
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
