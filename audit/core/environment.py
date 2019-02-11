import os
import sys
import platform
import json
import warnings
import requests
from queue import Queue


class Environment:

    class __Environment:
        def __init__(self):

            self.vulners_api_key = "OBE85DLS8WSOP5FM1DFWPUIDXK1D32UIS8FP3J4JG7IOKF9JP0WY0KH6YCTRC1UP"
            self.base_path = os.getcwd()
            self.path_certs = get_path_certs(self.base_path)
            self.path_download_files = self.base_path + "/resources/downloads"
            self.path_streams = self.base_path + "/resources/streams"
            self.path_firewall_resources = self.base_path + "/resources/firewall_resources"
            self.path_database = self.base_path + "/resources/db"
            self.path_embedded_scripts = self.base_path + "/resources/scripts"

            # create path dirs
            if not os.path.exists(self.base_path+"/resources"):
                os.mkdir(self.base_path+"/resources")
            if not os.path.exists(self.path_streams):
                os.mkdir(self.path_streams)
            if not os.path.exists(self.path_download_files):
                os.mkdir(self.path_download_files)
            if not os.path.exists(self.path_firewall_resources):
                os.mkdir(self.path_firewall_resources)
            if not os.path.exists(self.path_database):
                os.mkdir(self.path_database)
            if not os.path.exists(self.path_embedded_scripts):
                os.mkdir(self.path_embedded_scripts)

            features = get_features()

            self.private_ip = features["local_ip"]
            self.public_ip = "could not resolve public ip due to network error"
            self.has_internet = False
            try:
                self.public_ip = str(requests.get('https://api.ipify.org').text)
                self.has_internet = True
            except Exception as e:
                warnings.warn(str(e))
            self.os = features["os"]
            self.distro = features["distro"]
            self.distro_name = features["distro_name"]
            self.system_version = features["version"]
            self.default_adapter = features["default_adapter"]
            self.default_gateway = features["default_gateway"]
            self.codec_type = features["codec_type"]
            self.time_retrieve_network_sniffer = 100
            self.time_analysis_network = 20

            # managers
            self.packetManager = None
            self.firewallManager = None
            self.networkNeuralClassifierManager = None

    instance = None

    def __new__(cls, *args, **kwargs):
        if not Environment.instance:
            Environment.instance = Environment.__Environment()
        return Environment.instance

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __setattr__(self, name, value):
        return setattr(self.instance, name, value)


def get_path_certs(base_path):
    if hasattr(sys, "_MEIPASS"):  # Pyinstaller arguments
        return os.path.join(sys._MEIPASS, "certs")
    else:
        return base_path + "/resources/certs"


def get_features():
    system_platform = platform.system()
    if system_platform == "Windows":
        from audit.windows import get_features as windows_features
        return windows_features()
    elif system_platform == "Linux":
        from audit.linux import get_features as linux_features
        return linux_features()
    elif system_platform == "Darwin":
        from audit.darwin import get_features as darwin_features
        return darwin_features()
    else:
        raise Exception("platform not supported")


def define_managers():
    if Environment().os == "Windows":
        from audit.windows.packet_manager import WindowsPacketManager
        from audit.windows.firewall_manager import WindowsFirewallManager
        Environment().__setattr__("packetManager", WindowsPacketManager(Environment().path_download_files))
        Environment().__setattr__("firewallManager", WindowsFirewallManager())
    elif Environment().os == "Linux":
        from audit.linux.packet_manager import get_suitable_packet_manager
        from audit.linux.firewall_manager import LinuxFirewallManager
        Environment().__setattr__("packetManager", get_suitable_packet_manager(Environment().path_download_files))
        Environment().__setattr__("firewallManager", LinuxFirewallManager(Environment().path_embedded_scripts))
    elif Environment().os == "Darwin":
        from audit.darwin.packet_manager import DarwinPacketManager
        from audit.darwin.firewall_manager import DarwinFirewallManager
        Environment().__setattr__("packetManager", DarwinPacketManager(Environment().path_download_files))
        Environment().__setattr__("firewallManager", DarwinFirewallManager())
    else:
        raise Exception("platform not supported")


def check_system(queue: Queue):
    from audit.core.network import sniffer, NetworkMeasure, NetworkNeuralClassifierManager

    if not Environment().has_internet:
        queue.put("logger_info@Internet connection ---> NO")
        queue.put("logger_info@please verify your connection and try it again!")
        return False
    else:
        queue.put("logger_info@Internet connection ---> OK")
    try:
        import pcap
        queue.put("logger_info@Pcap installed ---> OK")
    except Exception as e:
        queue.put("logger_info@Pcap installed ---> NO")
        Environment().packetManager.install_package(queue, "pcap", queue_type="logger_info@")
        queue.put("logger_info@You need to reinitialize your system!")
        return False
    if not os.path.isfile(Environment().path_streams + "/network_data.json"):
        result = dict()
        queue.put("logger_info@generating network files... let's start use internet")
        queue.put("logger_info@")
        data = sniffer(Environment().time_retrieve_network_sniffer, queue, queue_type="logger_update@")
        queue.put("logger_info@network information collected successfully")
        result["input"] = NetworkMeasure.list_to_array_data(data["input"])
        result["output"] = NetworkMeasure.list_to_array_data(data["output"])
        with open(Environment().path_streams + '/network_data.json', 'w') as fp:
            json.dump(result, fp, sort_keys=True, indent=4)
        queue.put("logger_info@network structure generated")
    else:
        queue.put("logger_info@Network structure ---> OK")
    if Environment().networkNeuralClassifierManager is None:
        queue.put("logger_info@generating anomaly model...")
        Environment().networkNeuralClassifierManager = \
            NetworkNeuralClassifierManager(Environment().path_streams + '/network_data.json')
        queue.put("logger_info@network anomaly model generated")
    else:
        queue.put("logger_info@Anomaly model ---> OK")

    if not os.path.isfile(Environment().path_streams + "/vulners.json"):
        queue.put("logger_info@generating vulnerabilities model...")
        queue.put("logger_info@")
        Environment().packetManager.retrieve_vulners(queue, queue_type="logger_update@")
        queue.put("logger_info@vulnerabilities model generated")
    else:
        queue.put("logger_info@Vulnerabilities model ---> OK")
    queue.put("logger_info@finishing...")
    return True

