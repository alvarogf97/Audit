import json
import os
import warnings
from audit.database.user import User, init_db
from multiprocessing import Queue
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

    def __init__(self, port, queue: Queue, open_on_router=False, send_mail=False, mail=""):

        self.queue = queue

        if open_on_router:
            self.queue.put("logger_info@Trying to open port on router...")
            self.isOpen, self.time_port, self.port = open_port(port)
        else:
            self.isOpen = False
            self.time_port = 0
            self.port = port

        if send_mail:
            self.queue.put("logger_info@Sending email to " + mail)
            send_ip(self.port, mail)

        self.connection = Connection(port)
        self.active_processes = dict()
        self.current_user = None

        init_db()
        define_managers()

    def serve_forever(self):
        self.queue.put("server_info@server located on: " + Environment().private_ip + ":" + str(self.port))
        self.queue.put("server_info@public ip: " + Environment().public_ip)
        self.queue.put("server_info@port status: " + str(self.isOpen))
        request_query = dict()

        while True:
            error = False
            self.queue.put("logger_info@waiting for a connection")
            request_query["command"] = ""

            try:
                self.connection.accept()
                first_response = {"status": True, "data": os.getcwd()}
                self.connection.send_msg(self.parse_json(first_response))
                logging_query = self.parse_string(self.connection.recv_msg())
                self.current_user = User.check_user(name=logging_query["name"], password=logging_query["password"])
                if self.current_user is None:
                    raise Exception
                self.connection.send_msg(self.parse_json(first_response))
                self.queue.put("logger_info@ User: " + self.current_user.name +
                               " from: " + str(self.connection.get_client_address()) + " connected")
            except Exception as e:
                if self.connection.has_connection():
                    self.connection.send_msg(self.parse_json({"satus": False, "data": os.getcwd()}))
                error = True
                warnings.warn(str(e))
                self.queue.put("logger_info@insecure connection closed")

            if self.connection.has_connection() and not error:

                try:

                    while request_query["command"] != "exit":
                        check_active_processes(self.active_processes)
                        request_query = self.parse_string(self.connection.recv_msg())

                        if request_query["command"].startswith("cd"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(cd(request_query["args"])))

                        elif request_query["command"].startswith("ps"):
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

                        elif request_query["command"].startswith("kill"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(kill_process(request_query["args"])))

                        elif request_query["command"].startswith("ports"):
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

                        elif request_query["command"].startswith("HWinfo"):
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
                                                            "device_name": 
                                                                {
                                                                    "mountpoint": str
                                                                    "format": str
                                                                    "features": str
                                                                    "total": str
                                                                    "used": str
                                                                    "free": str
                                                                    "used_percent": str
                                                                }
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

                        elif request_query["command"].startswith("network analysis new"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(network_analysis(self.active_processes, True)))

                        elif request_query["command"].startswith("network analysis"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str
                                    }
                            """
                            self.connection.send_msg(self.parse_json(network_analysis(self.active_processes, False)))

                        elif request_query["command"].startswith("upnp devices"):
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

                        elif request_query["command"].startswith("upnp exec"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : args_out
                                    }
                            """
                            self.connection.send_msg(self.parse_json(upnp_execute_action(request_query["args"])))

                        elif request_query["command"].startswith("vulners new"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str or vulners
                                    }
                            """
                            self.connection.send_msg(self.parse_json(
                                Environment().packetManager.scan(self.active_processes, True)))

                        elif request_query["command"].startswith("vulners"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str or vulners
                                    }
                            """
                            self.connection.send_msg(self.parse_json(
                                Environment().packetManager.scan(self.active_processes, False)))

                        elif request_query["command"].startswith("firewall"):
                            """
                                response =
                                    {
                                        "status" : boolean
                                        "data" : str or rules
                                    }
                            """
                            Environment().firewallManager.execute_firewall_action(request_query["command"],
                                                                                  request_query["args"])

                        elif request_query["command"].startswith("restart"):
                            restart()

                        elif request_query["command"].startswith("get"):
                            get(self.connection, request_query["command"])

                        elif request_query["command"].startswith("send"):
                            try:
                                send(self.connection, request_query["command"])
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
                            self.connection.send_msg(self.parse_json(exec_command(request_query["command"])))

                except Exception as e:
                    warnings.warn(str(e))
                    self.connection.close_connection()

    def close(self):
        self.connection.close()

    @staticmethod
    def parse_json(json_item) -> str:
        return json.dumps(json_item, sort_keys=True, indent=4)

    @staticmethod
    def parse_string(query_str: str):
        return json.loads(query_str)

