import json
import multiprocessing
import os
import time
import warnings
import requests
import vulners
from multiprocessing import Queue
from typing import List, Dict
from abc import abstractmethod
from audit.core.core import shell_command, communicate, restart
from audit.core.environment import Environment


class Package:

    def __init__(self, name: str, version: str, full_name=None):
        self.name = name
        self.version = version
        self.full_name = full_name

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
                 published: str, last_seen: str, reporter: str):

        self.title = title
        self.score = score
        self.href = href
        self.published = published
        self.last_seen = last_seen
        self.reporter = reporter

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
        self.last_msg = ""

    @abstractmethod
    def get_installed_packets(self) -> List[Package]: pass

    def get_vulnerabilities(self, queue: Queue, queue_type="") -> Dict[Package, List[Vulnerability]]:
        queue.put("getting installed packets")
        packages = self.get_installed_packets()
        packages.append(Package(Environment().os, Environment().system_version.split(".")[0]))
        vulnerabilities = dict()
        packet_counter = 1
        for packet in packages:
            queue.put(queue_type + "examined " + str(packet_counter) + "/" + str(len(packages)))
            vulners_api = vulners.Vulners(api_key=Environment().vulners_api_key)
            search = None
            while search is None:
                try:
                    search = vulners_api.softwareVulnerabilities(packet.name, packet.version.split(".")[0], 3)
                except Exception as e:
                    warnings.warn(str(e))
                    search = None
            if search != {}:
                vulnerabilities[packet] = []
                search = [search.get(key) for key in search if key not in ['info', 'blog', 'bugbounty']]
                for type_vulner in search:
                    for vulner in type_vulner:
                        v = Vulnerability(title=vulner.get("title"),
                                          score=vulner.get("cvss").get("score"),
                                          href=vulner.get("href"),
                                          published=vulner.get("published"),
                                          last_seen=vulner.get("lastseen"),
                                          reporter=vulner.get("reporter"))
                        vulnerabilities[packet].append(v)
            packet_counter += 1
        return vulnerabilities

    # install_package will install package in system
    def install_package(self, queue: Queue, name: str, queue_type=""):
        cwd = os.getcwd()
        installed = True
        try:
            queue.put(queue_type + name + " will be installed on system")
            os.chdir(self.path_download_files)
            url, filename, commands = self.applications[name]
            if name in self.dependencies.keys():
                # first we need to install dependencies
                queue.put(queue_type + "dependencies: " + str(self.dependencies[name]))
                for dependency in self.dependencies[name]:
                    self.install_package(queue, dependency, queue_type=queue_type)
            requirement = requests.get(url)
            with open(filename, "wb") as f:
                f.write(requirement.content)
            for command in commands:
                print(command)
                if command.startswith("cd"):
                    os.chdir(command.split("$")[1])
                else:
                    shell_command(command)
                stdout, stderr = communicate()
                if stderr != "":
                    raise Exception
            # restart()
        except Exception as e:
            warnings.warn(str(e))
            queue.put(queue_type + "fail")
            installed = False
        os.chdir(cwd)
        if installed:
            queue.put(queue_type + "installed successfully")
        return

    @staticmethod
    def remap_keys(dictionary: Dict[Package, List[Vulnerability]]):
        res = []
        for package, vulnerabilities in dictionary.items():
            vulnerabilities_list = [vulner.__serialize__() for vulner in vulnerabilities]
            res.append({"Package": package.__serialize__(), "Vulnerabilities": vulnerabilities_list})
        with open(Environment().path_streams + '/vulners.json', 'w') as fp:
            json.dump(res, fp, sort_keys=True, indent=4)
        return

    def retrieve_vulners(self, queue: Queue, queue_type=""):
        self.remap_keys(self.get_vulnerabilities(queue, queue_type=queue_type))

    def scan(self, processes_active, new: bool):
        result = dict()
        if "vulners" in processes_active.keys():
            # communicate with subprocess
            queue = processes_active["vulners"][2]
            result["data"] = self.get_queue_msg(queue)
            result["status"] = False
        elif not os.path.isfile(Environment().path_streams + "/vulners.json") or new:
            queue = multiprocessing.Queue()
            vulners = multiprocessing.Process(target=self.retrieve_vulners, args=(queue,))
            vulners.start()
            processes_active["vulners"] = (vulners, time.time(), queue)
            result["data"] = "launch scanner"
            result["status"] = False
            self.last_msg = result
        else:
            if not isinstance(self.last_msg, Dict):
                with open(Environment().path_streams + "/vulners.json", "r") as f:
                    output = json.loads(f.read())
                result["data"] = output
                result["status"] = True
                self.last_msg = output
            else:
                result["data"] = self.last_msg
                result["status"] = True
        return result

    def get_queue_msg(self, queue: Queue):
        try:
            last = queue.get(timeout=2)
            self.last_msg = last
        except Exception as e:
            warnings.warn(str(e))
            last = self.last_msg
        return last
