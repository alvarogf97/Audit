import os
import sys
import platform
import requests


class Environment:

    class __Environment:
        def __init__(self):

            self.base_path = os.getcwd() + "/resources"
            self.path_certs = get_path_certs(self.base_path)
            self.path_download_files = self.base_path + "/downloads"
            self.path_streams = self.base_path + "/streams"

            features = get_features()

            self.private_ip = features["local_ip"]
            self.public_ip = str(requests.get('https://api.ipify.org').text)
            self.os = features["os"]
            self.default_adapter = features["default_adapter"]
            self.default_gateway = features["default_gateway"]
            self.codec_type = features["codec_type"]
            self.packetManager = None
            self.time_retrieve_network_sniffer = 60
            self.time_analysis_network = 0

            # create path dirs
            if not os.path.exists(self.base_path):
                os.mkdir(self.base_path)
            if not os.path.exists(self.path_streams):
                os.mkdir(self.path_streams)
            if not os.path.exists(self.path_download_files):
                os.mkdir(self.path_download_files)

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
        return base_path + "/certs"


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


def define_manager():
    if Environment().os == "Windows":
        from audit.windows.packet_manager import WindowsPacketManager
        Environment().__setattr__("packetManager",WindowsPacketManager(Environment().path_download_files))
    elif Environment().os == "Linux":
        from audit.linux.packet_manager import LinuxPacketManager
        Environment().__setattr__("packetManager",LinuxPacketManager(Environment().path_download_files))
    elif Environment().os == "Darwin":
        from audit.darwin.packet_manager import DarwinPacketManager
        Environment().__setattr__("packetManager",DarwinPacketManager(Environment().path_download_files))
    else:
        raise Exception("platform not supported")
