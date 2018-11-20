import warnings

import upnpclient
from audit.core.connection import Connection


def upnp(connection: Connection):
    # Show available devices
    responses = ""
    responses += "Upnp devices->\n"
    devices = upnpclient.discover(7)
    available_actions = []
    for device in devices:
        responses += (" device --> " + device.friendly_name + "\n")
        for service in device.services:
            responses += "     service --> " + service.service_id + "\n"
            for action in service.actions:
                responses += "         " + str(len(available_actions)) + "  action --> " + action.name + "\n"
                available_actions.append(action)
    responses += "\nchoose an available action or write exit to go back"
    connection.send_msg(responses)
    command = connection.recv_msg()
    while command != "exit":
        try:
            action_number = int(command)
            selected_action = available_actions[action_number]
            connection.send_msg("1")  # send ok
            connection.send_msg(str(len(selected_action.argsdef_in)))
            args = dict()
            for arg_name, statevar in selected_action.argsdef_in:
                connection.send_msg(arg_name + "(" + statevar["datatype"] + ")")
                args[arg_name] = connection.recv_msg()
            # execute action
            result = selected_action(**args)
            connection.send_msg("1")  # execution sucessfully
            if result:
                connection.send_msg(str(len(result)))
                for key in result.keys():
                    connection.send_msg(key + " = " + str(result[key]))
            else:
                connection.send_msg("1")
                connection.send_msg("invocation successfully")
        except Exception as e:
            warnings.warn(str(e))
            connection.send_msg("0")  # send fails
        command = connection.recv_msg()  # get new command
