import codecs
import warnings
from multiprocessing import Queue

import vulners
from typing import List, Dict
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package, Vulnerability
from audit.linux.packet_manager import LinuxPacketManager


class RHELPacketManager(LinuxPacketManager):

    def __init__(self, path_download_files: str):
        super().__init__(path_download_files)

    def get_installed_packets(self) -> List[Package]:
        packages = []
        shell_command("rpm -qa")
        stdout_file = codecs.open(Environment().path_streams + "/stdout.txt",
                                  mode="rb", encoding=Environment().codec_type,
                                  errors="replace")
        line = stdout_file.readline()
        while line:
            full_name = line
            splitted = line.split("-")
            line = stdout_file.readline()
            name = "-".join(splitted[0:(len(splitted) - 2)])
            version_splitted = "-".join(splitted[(len(splitted) - 2):len(splitted)]).split(".")
            version = ".".join(version_splitted[0:len(version_splitted) - 1])
            packages.append(Package(name, version, full_name))
        stdout_file.close()
        return packages

    def get_vulnerabilities(self, queue: Queue) -> Dict[Package, List[Vulnerability]]:
        queue.put("getting installed packets")
        packages = self.get_installed_packets()
        packages.append(Package(Environment().os, Environment().system_version.split(".")[0]))
        vulnerabilities = dict()
        packet_counter = 1
        for packet in packages:
            queue.put("examined " + str(packet_counter) + "/" + str(len(packages)))
            vulners_api = vulners.Vulners(api_key=Environment().vulners_api_key)
            search = None
            while search is None:
                try:
                    search = vulners_api.audit(os=Environment().distro,
                                               os_version=Environment().system_version,
                                               package=[packet.full_name])
                except Exception as e:
                    warnings.warn(str(e))
                    search = None
            if search != {}:
                vulnerabilities[packet] = []
                title = Environment().distro + " vulnerability on " + str(packet)
                v = Vulnerability(title=title,
                                  score=search.get("cvss").get("score"),
                                  href=search.get("href"),
                                  published=search.get("published"),
                                  last_seen=search.get("lastseen"),
                                  reporter=search.get("reporter"),
                                  cumulative_fix=search.get("cumulative_fix"))
                vulnerabilities[packet].append(v)
            packet_counter += 1
        return vulnerabilities
