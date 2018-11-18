import codecs
from typing import List
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package


def get_packages_on_arch() -> List[Package]:
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
