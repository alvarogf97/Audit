import warnings
import upnpclient


def upnp_devices_information():
    result = dict()
    result["status"] = True
    result["data"] = []
    devices = upnpclient.discover(5)
    for device in devices:
        device_json = dict()
        device_json["location"] = device.location
        device_json["name"] = device.friendly_name
        device_json["services"] = []
        for service in device.services:
            service_json = dict()
            service_json["id"] = service.service_id
            service_json["actions"] = []
            for action in service.actions:
                action_json = dict()
                action_json["name"] = action.name
                action_json["args_in"] = parse_args(action.argsdef_in)
                action_json["args_out"] = parse_args(action.argsdef_out)
                action_json["url"] = device.location
                service_json["actions"].append(action_json)
            device_json["services"].append(service_json)
        result["data"].append(device_json)
    return result


def parse_args(items):
    result = []
    for item in items:
        result_dict = dict()
        item_dict = item[1]
        name = item[0]
        result_dict["name"] = name
        result_dict["datatype"] = str(item_dict["datatype"])
        result.append(result_dict)
    return result


def upnp_execute_action(information):
    result = dict()
    device = upnpclient.Device(information["location"])
    service_id = information["service"]
    action_name = information["action"]
    found = False
    i = 0
    action = None

    while i < len(device.services) and not found:
        j = 0
        result_service = device.services[i]
        if result_service.service_id == service_id:
            while j < len(device.services[i].actions) and not found:
                result_action = device.services[i].actions[j]
                if result_action.name == action_name:
                    action = result_action
                    found = True
                j += 1
        i += 1

    args_in = information["args_in"]
    for arg, value in args_in.items():
       try:
           args_in[arg] = int(value)
       except Exception as e:
           # stub
           warnings.warn(str(e))

    try:
        action_exec = action(args_in)
        result["data"] = action_exec
        result["status"] = True
    except Exception as e:
        warnings.warn(str(e))
        result["status"] = False
        result["data"] = str(e)

    return result
