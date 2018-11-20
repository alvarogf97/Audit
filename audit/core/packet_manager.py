import json
import os
from typing import List, Dict
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

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __hash__(self):
        return self.name.__hash__() + self.version.__hash__()

    def __serialize__(self):
        return {"name": self.name, "version": self.version}


class Vulnerability:

    def __init__(self, title: str, score: str, href: str,
                 published: str, last_seen: str, reporter: str,
                 cumulative_fix: str):

        self.title = title
        self.score = score
        self.href = href
        self.published = published
        self.last_seen = last_seen
        self.reporter = reporter
        self.cumulative_fix = cumulative_fix
        if self.cumulative_fix is None:
            self.cumulative_fix = "Wait for upgrade"

    def __eq__(self, other):
        res = False
        if isinstance(other, self.__class__):
            for attr in self.__dict__.keys():
                if self.__getattribute__(attr) is not None and other.__getattribute__(attr) is not None:
                    res = self.__getattribute__(attr) == other.__getattribute__(attr)
                else:
                    res = False
        return res

    def __str__(self):
        res = ""
        for attr, value in self.__dict__.items():
            if value is not None:
                res += attr.title() + ": " + str(value) + "\n"
        return res

    def __serialize__(self):
        res = dict()
        for attr, value in self.__dict__.items():
            if value is not None:
                res[attr.title()] = str(value)
        return res


class PacketManager:

    def __init__(self, path_download_files: str, applications, dependencies):
        self.path_download_files = path_download_files
        self.applications = applications
        self.dependencies = dependencies

    @abstractmethod
    def get_installed_packets(self) -> List[Package]: pass

    @abstractmethod
    def get_vulnerabilities(self) -> Dict[Package, List[Vulnerability]]: pass

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

    @staticmethod
    def remap_keys(dictionary: Dict[Package, List[Vulnerability]]):
        res = []
        for package, vulnerabilities in dictionary.items():
            vulnerabilities_list = [vulner.__serialize__() for vulner in vulnerabilities]
            res.append({"Package": package.__serialize__(), "Vulnerabilities": vulnerabilities_list})
        res = json.dumps(res, sort_keys=True, indent=4)
        return res
