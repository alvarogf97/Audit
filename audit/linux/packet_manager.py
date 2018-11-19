import distro
from typing import List
from audit.core.packet_manager import PacketManager, Package


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

    # if distro is not supported returned empty list
    def get_installed_packets(self)-> List[Package]:
        sys_name = distro.id()
        if sys_name == "ubuntu" or sys_name == "debian":
            from audit.linux.distributions.debian import get_packages_on_debian
            packages = get_packages_on_debian()
        elif sys_name == "arch":
            from audit.linux.distributions.arch import get_packages_on_arch
            packages = get_packages_on_arch()
        else:
            from audit.linux.distributions.rpm import get_packages_on_rpm
            packages = get_packages_on_rpm()
        return packages
