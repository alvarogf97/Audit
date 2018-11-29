from abc import abstractmethod
from multiprocessing import Queue
from typing import List, Dict
from audit.core.environment import Environment
from audit.core.packet_manager import PacketManager, Package, Vulnerability


class LinuxPacketManager(PacketManager):

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

    @abstractmethod
    def get_installed_packets(self)-> List[Package]: pass

    @abstractmethod
    def get_vulnerabilities(self,queue: Queue) -> Dict[Package, List[Vulnerability]]: pass


def get_suitable_packet_manager(path_download_files: str) -> LinuxPacketManager:
    sys_name = Environment().distro
    if sys_name == "debian":
        from audit.linux.distributions.debian_based import DebianPacketManager
        return DebianPacketManager(path_download_files)
    elif sys_name == "arch":
        from audit.linux.distributions.arch_based import ArchPacketManager
        return ArchPacketManager(path_download_files)
    else:
        from audit.linux.distributions.rhel_based import RHELPacketManager
        return RHELPacketManager(path_download_files)
