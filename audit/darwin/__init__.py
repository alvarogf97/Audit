import platform
from audit.core.ip_utils import get_ip_info


def get_features():
    features = dict()
    features["os"] = "Darwin"
    features["distro"] = None
    features["version"] = platform.version()
    ip_info = get_ip_info()
    features["local_ip"] = ip_info[0]
    features["default_adapter"] = ip_info[1]
    features["default_gateway"] = ip_info[2]
    features["codec_type"] = "utf-8"
    features["reboot_command"] = "reboot"
    return features
