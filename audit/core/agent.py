import os
from audit.core.connection import Connection
from audit.core.core import check_active_processes, cd, get_processes, kill_process, restart, exec_command
from audit.core.device import retrieve_device_information
from audit.core.environment import Environment, define_managers
from audit.core.file_protocols import get, send
from audit.core.ip_utils import send_ip
from audit.core.network import get_ports_open_by_processes, network_analysis, watch_traffic
from audit.core.port_forwarding import open_port
from audit.core.upnp import upnp


class Agent:

    def __init__(self, port, open_on_router=False, send_mail=False):

        if open_on_router:
            self.isOpen, self.time_port, self.port = open_port(port)
        else:
            self.isOpen = False
            self.time_port = 0
            self.port = port

        if send_mail:
            send_ip(self.port)

        self.connection = Connection(port)
        self.active_processes = dict()
        define_managers()

    def serve_forever(self):
        print("server located on: " + Environment().private_ip + ":" + str(self.port))
        print("port status: " + str(self.isOpen))
        while True:
            command = " "
            print("waiting for a connection")
            try:
                self.connection.accept()
                print(str(self.connection.get_client_address()) + " connected")
            except:
                print("insecure connection closed")
            if self.connection.has_connection():
                try:
                    self.connection.send_msg(os.getcwd())
                    while command != "exit":
                        check_active_processes(self.active_processes)
                        command = self.connection.recv_msg()
                        if command.startswith("cd"):
                            cd(self.connection, command)
                        elif command.startswith("ps"):
                            get_processes(self.connection)
                        elif command.startswith("kill"):
                            kill_process(self.connection, command)
                        elif command.startswith("get"):
                            get(self.connection, command)
                        elif command.startswith("send"):
                            try:
                                send(self.connection, command)
                            except IOError as error:
                                print(" file not found")
                        elif command.startswith("disable firewall"):
                            self.connection.send_msg("not implemented yet")
                        elif command.startswith("ports"):
                            get_ports_open_by_processes(self.connection)
                        elif command.startswith("HWinfo"):
                            retrieve_device_information(self.connection)
                        elif command.startswith("help"):
                            pass  # only in client side, but do-nothing
                        elif command.startswith("network analysis new"):
                            network_analysis(self.connection, self.active_processes, True)
                        elif command.startswith("network analysis"):
                            network_analysis(self.connection, self.active_processes, False)
                        elif command.startswith("upnp devices"):
                            upnp(self.connection)
                        elif command.startswith("watch traffic"):
                            watch_traffic(self.connection)
                        elif command.startswith("restart"):
                            restart()
                        elif command.startswith("firewall"):
                            Environment().firewallManager.start(self.connection)
                        elif command.startswith("vulners"):
                            dictionary = Environment().packetManager.get_vulnerabilities()
                            self.connection.send_msg(Environment().packetManager.remap_keys(dictionary))
                        else:
                            exec_command(self.connection, command)
                        self.connection.send_msg(os.getcwd())  # always send CWD
                except:
                    self.connection.close_connection()
