from typing import List

from audit.core.packet_manager import PacketManager, Package


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

    def get_installed_packets(self)-> List[Package]:
        packages = []
        # TO-DO
        return packages
