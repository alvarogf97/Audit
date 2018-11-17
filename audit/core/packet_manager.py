import os
from typing import List

import requests
from abc import abstractmethod
from audit.core.connection import Connection
from audit.core.core import shell_command, communicate


class Package:

    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version

    def __str__(self):
        return "Name: " + self.name + "    Version: " + self.version


class PacketManager:

    def __init__(self, path_download_files: str, applications, dependencies):
        self.path_download_files = path_download_files
        self.applications = applications
        self.dependencies = dependencies

    @abstractmethod
    def get_installed_packets(self) -> List[Package]: pass

    # install_package will install package in system
    # 0:error
    # 1:installed
    def install_package(self, connection: Connection, name: str, tab=""):
        cwd = os.getcwd()
        try:
            connection.send_msg(tab + name + " will be installed on system")
            os.chdir(self.path_download_files)
            url, filename, commands = self.applications[name]
            if name in self.dependencies.keys():
                # first we need to install dependencies
                connection.send_msg(tab + "dependencies: " + str(self.dependencies[name]))
                for dependency in self.dependencies[name]:
                    result = self.install_package(connection, dependency, tab + "  ")
                    if result[0] == 0:
                        raise Exception(result[1])  # elevate exception
            requirement = requests.get(url)
            with open(filename, "wb") as f:
                f.write(requirement.content)
            for command in commands:
                if command.startswith("cd"):
                    os.chdir(command.split("$")[1])
                else:
                    shell_command(command)
            stdout, stderr = communicate()
            if not stderr == "":
                msg = (0, stderr)
            else:
                msg = (1, name + " installed successfully. rebooting system")
        except:
            msg = (0, "cannot install " + name)
        os.chdir(cwd)
        return msg
