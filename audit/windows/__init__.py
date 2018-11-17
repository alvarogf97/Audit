from audit.core.ip_utils import get_ip_info


def get_features():
    features = dict()
    features["os"] = "Windows"
    ip_info = get_ip_info()
    features["local_ip"] = ip_info[0]
    features["default_adapter"] = "\\Device\\NPF_" + ip_info[1]
    features["default_gateway"] = ip_info[2]
    features["codec_type"] = "cp1252"
    features["reboot_command"] = "shutdown -r -t 1"
    return features
