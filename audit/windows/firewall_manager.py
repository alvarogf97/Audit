from audit.core.connection import Connection
from audit.core.core import shell_command, communicate
from audit.core.firewall_manager import FirewallManager


class WindowsFirewallManager(FirewallManager):

    # name
    # interface
    # action
    # protocol
    # local port
    # program
    def add_rule(self, connection: Connection):

        kwargs = dict()
        command = "netsh advfirewall firewall add rule"

        connection.send_msg("6")

        connection.send_msg("name")
        name = connection.recv_msg()
        if name != "": kwargs["name"] = name

        connection.send_msg("interface")
        interface = connection.recv_msg()
        if interface != "": kwargs["interface"] = interface

        connection.send_msg("action")
        action = connection.recv_msg()
        if action != "": kwargs["action"] = action

        connection.send_msg("protocol")
        protocol = connection.recv_msg()
        if protocol != "": kwargs["protocol"] = protocol

        connection.send_msg("local port")
        local_port = connection.recv_msg()
        if local_port != "": kwargs["localport"] = local_port

        connection.send_msg("program")
        program = connection.recv_msg()
        if program != "": kwargs["program"] = program

        for key, value in kwargs.items():
            command += " " + key + "=" + value

        shell_command(command)
        stdout, stderr = communicate()

        if stdout != '':
            # send output
            connection.send_msg(stdout)
        else:
            # send error if something happen
            connection.send_msg(stderr)

    def remove_rule(self, connection: Connection): pass

    def get_rules(self, connection: Connection): pass

    def export_firewall(self, connection: Connection): pass

    def import_firewall(self, connection: Connection): pass

    def disable(self, connection: Connection): pass

    def enable(self, connection: Connection): pass

    def reset_to_default(self, connection: Connection): pass