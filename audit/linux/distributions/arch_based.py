import codecs
import warnings
from multiprocessing import Queue

import vulners
from typing import List, Dict
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package, Vulnerability
from audit.linux.packet_manager import LinuxPacketManager


class ArchPacketManager(LinuxPacketManager):

    def __init__(self, path_download_files: str):
        super().__init__(path_download_files)

    def get_installed_packets(self) -> List[Package]:
        packages = []
        shell_command("pacman -Q")
        stdout_file = codecs.open(Environment().path_streams + "/stdout.txt",
                                  mode="rb", encoding=Environment().codec_type,
                                  errors="replace")
        line = stdout_file.readline()
        while line:
            splitted = line.replace("\n", "").split(" ")
            packages.append(Package(splitted[0], splitted[1]))
            line = stdout_file.readline()
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
                                          reporter=vulner.get("reporter"),
                                          cumulative_fix=vulner.get("cumulative_fix"))
                        vulnerabilities[packet].append(v)
            packet_counter += 1
        return vulnerabilities
