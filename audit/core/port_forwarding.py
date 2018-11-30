import warnings
import upnpclient
from audit.core.environment import Environment


def not_in(igd_actions, action):
    result = False
    i = 0

    while i < len(igd_actions) and not result:
        if igd_actions[i].name == action.name:
            result = True

    return result


def search_igd_port_actions():
    # search for devices which has WANIPConn1.AddPortMapping
    devices = upnpclient.discover(7)
    igd_actions = []
    for router in [device for device in devices if Environment().default_gateway in device.location]:
        for service in router.services:
            for action in service.actions:
                if "AddPortMapping" in action.name and not not_in(igd_actions, action):
                    igd_actions.append(action)

    return igd_actions


# open_port forward port connections to local ip in public ip if is free
def open_port(port, actions=None, times=0):
    time_open = 10000
    # We will try to open ports on all IGD
    if actions is None:
        actions = search_igd_port_actions()
    ok = (len(actions) != 0 and times<5, time_open, port)  # no IGD found
    if times < 5:
        for action in actions:
            # first close port and re-open it
            try:
                action(
                    NewRemoteHost=Environment().private_ip,
                    NewExternalPort=port,
                    NewProtocol='TCP',
                    NewInternalPort=port,
                    NewInternalClient=Environment().private_ip,
                    NewEnabled='1',
                    NewPortMappingDescription='Testing',
                    NewLeaseDuration=time_open)
            except Exception as e:
                # if fails, we will try in another port
                warnings.warn(str(e))
                ok = open_port(port+1, actions)
    return ok
