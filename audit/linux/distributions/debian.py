import codecs
from typing import List
from audit.core.core import shell_command
from audit.core.environment import Environment
from audit.core.packet_manager import Package


def get_packages_on_debian() -> List[Package]:
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
        packages.append(Package(name, version))
        line = stdout_file.readline()
    stdout_file.close()
    return packages
