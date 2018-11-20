import datetime
import os
import warnings

from audit.core.connection import Connection
from audit.core.core import exec_command, shell_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager
import iptc


class LinuxFirewallManager(FirewallManager):

    def start(self, connection: Connection):
        options = "1    add chain\n" \
                + "2    remove chain\n" \
                + "3    add rule\n" \
                + "4    remove rule\n" \
                + "5    get rules\n" \
                + "6    export firewall settings\n" \
                + "7    import firewall settings\n" \
                + "8    disable firewall\n" \
                + "9    enable firewall\n" \
                + "10    exit"
        connection.send_msg(options)
        option = connection.recv_msg()
        while option != "10":
                if option == "1":
                    self.add_chain(connection)
                elif option == "2":
                    self.remove_chain(connection)
                elif option == "3":
                    self.add_rule(connection)
                elif option == "4":
                    self.remove_rule(connection)
                elif option == "5":
                    self.get_rules(connection)
                elif option == "6":
                    self.export_firewall(connection)
                elif option == "7":
                    self.import_firewall(connection)
                elif option == "8":
                    self.disable(connection)
                elif option == "9":
                    self.enable(connection)
                option = connection.recv_msg()

    def add_chain(self, connection: Connection):
        name = connection.recv_msg()
        iptc.Table.FILTER.create_chain(name)

    def remove_chain(self, connection: Connection):
        name = connection.recv_msg()
        iptc.Table.FILTER.delete_chain(name)

    def add_rule(self, connection: Connection):

        kwargs = dict()
        connection.send_msg("5")  # number of params for client

        connection.send_msg("chain name")
        chain_name = connection.recv_msg()

        connection.send_msg("interface")
        interface = connection.recv_msg()
        if interface != "": kwargs["interface"] = interface

        connection.send_msg("src")
        src = connection.recv_msg()
        if src != "": kwargs["src"] = src

        connection.send_msg("action")
        action = connection.recv_msg()
        if action != "": kwargs["action"] = action

        connection.send_msg("protocol")
        protocol = connection.recv_msg()
        if protocol != "": kwargs["protocol"] = protocol

        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
        rule = iptc.Rule()
        if kwargs.get("interface") is not None: rule.in_interface = kwargs.get("interface")
        if kwargs.get("src") is not None: rule.src = kwargs.get("src")
        if kwargs.get("action") is not None: rule.create_target(kwargs.get("action"))
        if kwargs.get("protocol") is not None: rule.protocol = kwargs.get("protocol")
        chain.insert_rule(rule)

    def remove_rule(self, connection: Connection):
        rule_name = connection.recv_msg()
        table = iptc.Table(iptc.Table.FILTER)
        table.autocommit = False
        for chain in table.chains:
            for rule in chain.rules:
                if rule.target.name == rule_name:
                    chain.delete_rule(rule)
        table.commit()
        table.autocommit = True

    def get_rules(self, connection: Connection):
        result = ""
        table = iptc.Table(iptc.Table.ALL)
        for chain in table.chains:
            result += "Chain " + chain.name
            for rule in chain.rules:
                result += "Rule " + rule.target.name + "\n     proto: " + rule.protocol + "\n     src: " + rule.src, "\n     dst: " + \
                    rule.dst + "\n     in: " + rule.in_interface + "\n     out: " + rule.out_interface
        connection.send_msg(result)

    def export_firewall(self, connection: Connection):
        time_info = datetime.datetime.now()
        filename = str(time_info.year)+"_"+str(time_info.month)+"_"\
                   + str(time_info.day)+"_"+str(time_info.hour)+"_"\
                   + str(time_info.minute)+".wfw"
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/" + filename + "\""
        print(command)
        exec_command(connection, command)

    def import_firewall(self, connection: Connection):
        files = [f for f in os.listdir(Environment().path_firewall_resources)
                 if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]
        responses = "\n".join(files)
        connection.send_msg(responses)
        try:
            option = int(connection.recv_msg())
            filename = files[option]
            command = "iptables-restore < \"" + Environment().path_firewall_resources + "/" + filename + "\""
            exec_command(connection, command)
        except Exception as e:
            warnings.warn(str(e))
            connection.send_msg("option error")

    def disable(self, connection: Connection):
        command = "iptables-save > \"" + Environment().path_firewall_resources + "/last\""
        shell_command(command)
        shell_command("iptables -X")
        shell_command("iptables -t nat -F")
        shell_command("iptables -t nat -X")
        shell_command("iptables -t mangle -F")
        shell_command("iptables -t mangle -X")
        shell_command("iptables -P INPUT ACCEPT")
        shell_command("iptables -P FORWARD ACCEPT")
        exec_command(connection, "iptables -P OUTPUT ACCEPT")

    def enable(self, connection: Connection):
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/last\""
        exec_command(connection, command)
