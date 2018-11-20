import codecs
import warnings
import vulners
from typing import List, Dict
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import PacketManager, Package, Vulnerability


class DarwinPacketManager(PacketManager):

    def __init__(self, path_download_files: str):
        applications = {
            "pcap":
                ("https://www.tcpdump.org/release/libpcap-1.9.0.tar.gz",
                 "libpcap-1.9.0.tar.gz",
                 ["tar xvzf libpcap-1.9.0.tar.gz", "cd$./libpcap-1.9.0", "./configure", "make", "make install"]),
            "bison":
                ("http://ftp.gnu.org/gnu/bison/bison-3.2.tar.gz",
                 "bison-3.2.tar.gz",
                 ["tar xvzf bison-3.2.tar.gz", "cd$./bison-3.2", "./configure", "make", "make install"]),
            "flex":
                ("https://github.com/westes/flex/releases/download/v2.6.3/flex-2.6.3.tar.gz",
                 "flex",
                 ["tar xvzf flex-2.6.3.tar.gz", "cd$./flex-2.6.3", "./configure", "make", "make install"])
        }
        dependencies = {
            "pcap": ["bisonte", "flex"]
        }
        super().__init__(path_download_files, applications, dependencies)

    def get_installed_packets(self) -> List[Package]:
        shell_command("system_profiler SPApplicationsDataType")
        file = codecs.open(Environment().path_streams + "/stdout.txt",
                           mode="rb", encoding=Environment().codec_type,
                           errors="replace")
        packages = []

        file.readline()
        file.readline()
        line = file.readline()

        while line:
            name = line.replace(" ", "").replace("\n", "").replace(":", "")
            version = ""
            file.readline()  # whitespace
            sub_line = file.readline()
            while sub_line:
                if "Version:" in sub_line:
                    version = sub_line.replace(" ", "").replace("\n", "").replace("Version:", "")
                    sub_line = file.readline()
                elif ("Obtained from:" in sub_line or "Last Modified:" in sub_line
                      or "Kind:" in sub_line or "64-Bit (Intel):" in sub_line
                      or "Signed by:" in sub_line or "Location:" in sub_line
                      or "Get Info String:" in sub_line):
                    sub_line = file.readline()
                else:
                    sub_line = None
            line = file.readline()
            packages.append(Package(name, version.replace(",", ".")))
        return packages

    def get_vulnerabilities(self) -> Dict[Package, List[Vulnerability]]:
        packages = self.get_installed_packets()
        packages.append(Package(Environment().os, Environment().system_version.split(".")[0]))
        vulnerabilities = dict()
        for packet in packages:
            vulnerabilities[packet] = []
            vulners_api = vulners.Vulners(api_key=Environment().vulners_api_key)
            search = None
            while search is None:
                try:
                    search = vulners_api.softwareVulnerabilities(packet.name, packet.version.split(".")[0], 3)
                except Exception as e:
                    warnings.warn(str(e))
                    search = None
            search = [search.get(key) for key in search if key not in ['info', 'blog', 'bugbounty']]
            for type_vulner in search:
                for vulner in type_vulner:
                    v = Vulnerability(title=vulner.get("title"),
                                      score=vulner.get("cvss").get("score"),
                                      href=vulner.get("href"),
                                      published=vulner.get("published"),
                                      last_seen=vulner.get("last_seen"),
                                      reporter=vulner.get("lastseen"),
                                      cumulative_fix=vulner.get("cumulative_fix"))
                    vulnerabilities[packet].append(v)
        return vulnerabilities
