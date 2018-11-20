import warnings
import upnpclient
from audit.core.environment import Environment


# search_IGD get default internet gateway device
def search_igd():
    # search for devices which has WANIPConn1.AddPortMapping
    devices = upnpclient.discover(7)
    igd = []
    for router in [device for device in devices if Environment().default_gateway in device.location]:
        for service in router.services:
            for action in service.actions:
                if "AddPortMapping" in action.name and router not in igd:
                    igd.append(router)
    return igd


# open_port forward port connections to local ip in public ip if is free
def open_port(port, devices=None):
    time_open = 10000
    # We will try to open ports on all IGD
    if devices is None:
        devices = search_igd()
    ok = (len(devices) != 0, time_open, port)  # no IGD found
    for device in devices:
        # first close port and re-open it
        try:
            device.WANIPConn1.AddPortMapping(
                NewRemoteHost=Environment().private_ip,
                NewExternalPort=port,
                NewProtocol='TCP',
                NewInternalPort=port,
                NewInternalClient=Environment().private_ip,
                NewEnabled='1',
                NewPortMappingDescription='Testing',
                NewLeaseDuration=10000)
        except Exception as e:
            # if fails, we will try in another port
            warnings.warn(str(e))
            ok = open_port(port+1, devices)
    return ok
