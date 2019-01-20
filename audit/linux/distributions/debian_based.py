import codecs
from typing import List
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package
from audit.linux.packet_manager import LinuxPacketManager


class DebianPacketManager(LinuxPacketManager):

    def __init__(self, path_download_files: str):
        super().__init__(path_download_files)

    def get_installed_packets(self) -> List[Package]:
        packages = []
        shell_command("dpkg -l")
        stdout_file = codecs.open(Environment().path_streams + "/stdout.txt",
                                  mode="rb", encoding=Environment().codec_type,
                                  errors="replace")
        # first five lines are information only
        stdout_file.readline()
        stdout_file.readline()
        stdout_file.readline()
        stdout_file.readline()
        stdout_file.readline()
        line = stdout_file.readline()
        while line:
            splitted = line.split()
            name = splitted[1]
            version = splitted[2]
            full_name = name + " " + version + " " + splitted[3]
            packages.append(Package(name, version, full_name))
            line = stdout_file.readline()
        stdout_file.close()
        return packages

