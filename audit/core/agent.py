import json
import os
import warnings
from audit.core.connection import Connection
from audit.core.core import check_active_processes, cd, get_processes, kill_process, restart, exec_command
from audit.core.device import device_info
from audit.core.environment import Environment, define_managers
from audit.core.file_protocols import get, send
from audit.core.ip_utils import send_ip
from audit.core.network import get_ports_open_by_processes, network_analysis
from audit.core.port_forwarding import open_port
from audit.core.upnp import upnp_devices_information, upnp_execute_action


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
            except Exception as e:
                warnings.warn(str(e))
                print("insecure connection closed")

            if self.connection.has_connection():

                try:
                    first_response = {"status": True, "data": os.getcwd()}
                    self.connection.send_msg(self.parse_json(first_response))

                    while command != "exit":
                        check_active_processes(self.active_processes)
                        command = self.connection.recv_msg()

                        if command.startswith("cd"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(cd(command)))

                        elif command.startswith("ps"):
                            """
                                response =
                                        {
                                            "status" : True
                                            "data" :
                                                [
                                                    {
                                                        "pid": number
                                                        "name": str
                                                    },
                                                ]
                                        }
                            """
                            self.connection.send_msg(self.parse_json(get_processes()))

                        elif command.startswith("kill"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(kill_process(command)))

                        elif command.startswith("ports"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : 
                                            [
                                                {
                                                    "port": number
                                                    "processes":
                                                        [
                                                            {
                                                                "pid": number
                                                                "name": str
                                                            },
                                                        ]
                                                }   
                                            ]
                                    }
                            """
                            self.connection.send_msg(self.parse_json(get_ports_open_by_processes()))

                        elif command.startswith("HWinfo"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : 
                                            {
                                                "system": 
                                                    {
                                                        "platform":
                                                        "system_users":
                                                    }
                                                "cpu":
                                                    {
                                                        "processor": str
                                                        "architecture": str
                                                        "cores": str
                                                        "threads": str
                                                        "usage": [x | x: str] 
                                                    }
                                                "virtual_memory":
                                                    {
                                                        "total": str
                                                        "available": str
                                                        "used": str
                                                        "used_percent": str
                                                    }
                                                "disks": 
                                                    [
                                                        {
                                                            "device": str
                                                            "mountpoint": str
                                                            "format": str
                                                            "features": str
                                                            "total": str
                                                            "used": str
                                                            "free": str
                                                            "used_percent": str
                                                        },
                                                    ]
                                                "battery":
                                                    {
                                                        "percent": str
                                                        "remaining_time": str
                                                        "power": str
                                                    }    
                                            }
                                    }
                            """
                            self.connection.send_msg(self.parse_json(device_info()))

                        elif command.startswith("network analysis new"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(network_analysis(self.active_processes, True)))

                        elif command.startswith("network analysis"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(network_analysis(self.active_processes, False)))

                        elif command.startswith("upnp devices"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : 
                                            [
                                                {
                                                    "location": str
                                                    "name": str
                                                    "services:"
                                                        [
                                                            {
                                                                "id": str
                                                                "actions:"
                                                                    [
                                                                        {
                                                                            "name": str
                                                                            "args_in":
                                                                            "args_out":
                                                                            "url": str
                                                                        }
                                                                    ]
                                                            }
                                                        ]
                                                }
                                            ]
                                    }
                            """
                            self.connection.send_msg(self.parse_json(upnp_devices_information()))

                        elif command.startswith("upnp exec"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : args_out
                                    }
                            """
                            self.connection.send_msg(self.parse_json(upnp_execute_action(command.split("@")[1])))

                        elif command.startswith("vulners"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str or vulners
                                    }
                            """
                            self.connection.send_msg(self.parse_json(
                                Environment().packetManager.scan(self.active_processes, False)))

                        elif command.startswith("restart"):
                            restart()

                        elif command.startswith("firewall"):
                            Environment().firewallManager.start(self.connection)

                        elif command.startswith("get"):
                            get(self.connection, command)

                        elif command.startswith("send"):
                            try:
                                send(self.connection, command)
                            except IOError as error:
                                warnings.warn(str(error))
                                print(" file not found")

                        else:
                            """
                                response =
                                    {
                                        "status" : boolean
                                            "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(exec_command(command)))

                except Exception as e:
                    warnings.warn(str(e))
                    self.connection.close_connection()

    @staticmethod
    def parse_json(json_item) -> str:
        return json.dumps(json_item, sort_keys=True, indent=4)
