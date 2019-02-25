import codecs
from typing import List
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import PacketManager, Package, Vulnerability


class DarwinPacketManager(PacketManager):

    def __init__(self, path_download_files: str):
        applications = {
            "pcap":
                ("https://www.tcpdump.org/release/libpcap-1.9.0.tar.gz",
                 "libpcap-1.9.0.tar.gz",
                 [["tar xvzf libpcap-1.9.0.tar.gz", "decompressing file..."],
                  ["cd$./libpcap-1.9.0", "changing directory to installation folder"],
                  ["./configure", "configuring installation files"],
                  ["make", "compiling from source"],
                  ["make install", "installing..."]]),
            "bison":
                ("http://ftp.gnu.org/gnu/bison/bison-3.2.tar.gz",
                 "bison-3.2.tar.gz",
                 [["tar xvzf bison-3.2.tar.gz", "decompressing file..."],
                  ["cd$./bison-3.2", "changing directory to installation folder"],
                  ["./configure", "configuring installation files"],
                  ["make", "compiling from source"],
                  ["make install", "installing..."]]),
            "flex":
                ("https://github.com/westes/flex/releases/download/v2.6.3/flex-2.6.3.tar.gz",
                 "flex-2.6.3",
                 [["tar xvzf flex-2.6.3.tar.gz", "decompressing file..."],
                  ["cd$./flex-2.6.3", "changing directory to installation folder"],
                  ["./configure", "configuring installation files"],
                  ["make", "compiling from source"],
                  ["make install", "installing..."]])
        }
        dependencies = {
                    "pcap": ["bison v", "flex"]
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
