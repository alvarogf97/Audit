import codecs
from typing import List
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package
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
