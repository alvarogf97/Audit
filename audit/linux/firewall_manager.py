import datetime
import os
from audit.core.connection import Connection
from audit.core.core import exec_command, shell_command
from audit.core.environment import Environment
from audit.core.firewall_manager import FirewallManager
import iptc


class LinuxFirewallManager(FirewallManager):

    def add_chain(self, connection: Connection):
        name = connection.recv_msg()
        iptc.Table.FILTER.create_chain(name)

    def remove_chain(self, connection: Connection):
        name = connection.recv_msg()
        iptc.Table.FILTER.delete_chain(name)

    def add_rule(self, connection: Connection):
        name_chain = connection.recv_msg()
        # TO-DO

    def remove_rule(self, connection: Connection):
        rule_name = connection.recv_msg()
        table = iptc.Table(iptc.Table.FILTER)
        table.autocommit = False
        chain = iptc.Chain(table, "FORWARD")
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
        files = [f for f in os.listdir(Environment().path_firewall_resources) \
                 if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]
        responses = "\n".join(files)
        connection.send_msg(responses)
        try:
            option = int(connection.recv_msg())
            filename = files[option]
            command = "iptables-restore < \"" + Environment().path_firewall_resources + "/" + filename + "\""
            exec_command(connection, command)
        except:
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
        exec_command("iptables -P OUTPUT ACCEPT")

    def enable(self, connection: Connection):
        command = "iptables-restore < \"" + Environment().path_firewall_resources + "/last\""
        exec_command(command)
