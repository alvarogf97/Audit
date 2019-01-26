import distro
from audit.core.ip_utils import get_ip_info


def get_features():
    features = dict()
    features["os"] = "Linux"
    features["distro"] = get_distro_base(distro.id())
    features["distro_name"] = distro.id()
    features["version"] = distro.version()
    ip_info = get_ip_info()
    features["local_ip"] = ip_info[0]
    features["default_adapter"] = ip_info[1]
    features["default_gateway"] = ip_info[2]
    features["codec_type"] = "utf-8"
    features["reboot_command"] = "reboot"
    return features


def get_distro_base(distro_id: str) -> str:
    if (distro_id == "ubuntu" or
            distro_id == "debian" or
            distro_id == "kali" or
            distro_id == "lubuntu" or
            distro_id == "kubuntu" or
            distro_id == "grml" or
            distro_id == "tails"):
        distro_based = "debian"
    elif (distro_id == "arch" or
          distro_id == "apricity" or
          distro_id == "manjaro" or
          distro_id == "antergos"):
        distro_based = "arch"
    else:
        distro_based = "rhel"

    return distro_based
