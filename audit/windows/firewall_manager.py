import datetime
import os
from audit.core.connection import Connection
from audit.core.core import exec_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager


class WindowsFirewallManager(FirewallManager):

    def start(self, connection: Connection):
        options = "1    add rule\n" \
                + "2    remove rule\n" \
                + "3    get rules\n" \
                + "4    export firewall settings\n" \
                + "5    import firewall settings\n" \
                + "6    disable firewall\n" \
                + "7    enable firewall\n" \
                + "8    exit"
        connection.send_msg(options)
        option = connection.recv_msg()
        while option != "8":
                if option == "1":
                    self.add_rule(connection)
                elif option == "2":
                    self.remove_rule(connection)
                elif option == "3":
                    self.get_rules(connection)
                elif option == "4":
                    self.export_firewall(connection)
                elif option == "5":
                    self.import_firewall(connection)
                elif option == "6":
                    self.disable(connection)
                elif option == "7":
                    self.enable(connection)
                option = connection.recv_msg()

    # name
    # interface
    # action
    # protocol
    # local port
    # program
    def add_rule(self, connection: Connection):

        kwargs = dict()
        command = "netsh advfirewall firewall add rule dir=in"

        connection.send_msg("6")  # number of params for client

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

        exec_command(connection, command)

    def remove_rule(self, connection: Connection):
        connection.send_msg("1")  # number of params for client
        connection.send_msg("name")
        name = connection.recv_msg()
        command = "netsh advfirewall firewall delete rule name=" + name
        exec_command(connection, command)

    def get_rules(self, connection: Connection):
        command = "netsh advfirewall firewall show rule name=all"
        exec_command(connection, command)

    def export_firewall(self, connection: Connection):
        time_info = datetime.datetime.now()
        filename = str(time_info.year)+"_"+str(time_info.month)+"_"\
                   + str(time_info.day)+"_"+str(time_info.hour)+"_"\
                   + str(time_info.minute)+".wfw"
        command = "netsh advfirewall export \"" + Environment().path_firewall_resources + "/" + filename + "\""
        print(command)
        exec_command(connection, command)

    def import_firewall(self, connection: Connection):
        files = [f for f in os.listdir(Environment().path_firewall_resources) \
                 if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]
        responses = "\n".join(files)
        connection.send_msg(responses)
        try:
            option = int(connection.recv_msg())
            filename = files[option]
            command = "netsh advfirewall import \"" + Environment().path_firewall_resources + "/" + filename + "\""
            exec_command(connection, command)
        except:
            connection.send_msg("option error")

    def disable(self, connection: Connection):
        exec_command(connection, "netsh advfirewall set allprofiles state off")

    def enable(self, connection: Connection):
        exec_command(connection, "netsh advfirewall set allprofiles state on")