import json
import multiprocessing
import os
import socket
import time
import psutil
import dpkt
from audit.core.connection import Connection
from audit.core.core import restart
from audit.core.environment import Environment


# get_ports_open_by_processes send ports which are open by processes
def get_ports_open_by_processes(connection: Connection):
    process_ports = dict()
    for x in psutil.net_connections():
        if x.laddr.port in process_ports.keys() \
                and not process_ports.get(x.laddr.port) is None \
                and x.pid not in process_ports.get(x.laddr.port) \
                and (x.pid, psutil.Process(x.pid).name()) not in process_ports[x.laddr.port]:
            process_ports[x.laddr.port].append((x.pid, psutil.Process(x.pid).name()))
        else:
            process_ports[x.laddr.port] = [(x.pid, psutil.Process(x.pid).name())]
    # send number of ports
    connection.send_msg(str(len(process_ports)))
    for port, processes in sorted(process_ports.items()):
        connection.send_msg(str(port) + " --> " + str(processes))


# network_analysis inform about anomaly amount of data in packets
# 0: retrieve information in background
# 1: installing pcap
# 2: executing analysis
def network_analysis(connection: Connection, process_active, new: bool):
    if "sniffer" in process_active.keys():
        connection.send_msg("0")  # code 0: retrieve information in background
        connection.send_msg("collecting information in background. Time to left: " \
                            + str(max(Environment().time_retrieve_network_sniffer - (time.time() - process_active["sniffer"][1]), 0)) \
                            + "\nplease wait for it")
    elif not os.path.isfile(Environment().path_streams + "/data.json") or new:
        current_cwd = os.getcwd()
        try:
            import pcap
            os.chdir(Environment().base_path)
            sniffer = multiprocessing.Process(target=retrieve_in_background)
            sniffer.start()
            process_active["sniffer"] = (sniffer, time.time())  # Process create
            connection.send_msg("0")  # code 0: retrieve information in background
            connection.send_msg("Initializing analysis\ncollecting needed data\nTime to left: " \
                                + str(max(Environment().time_analysis_network + Environment().time_retrieve_network_sniffer - (time.time() - process_active["sniffer"][1]), 0)) \
                                + "\nplease wait for it")
        except:
            # Pcap not installed
            connection.send_msg("1")  # installing pcap
            msg = Environment().packetManager.install_package(connection, "pcap")
            connection.send_msg(msg[1])
            connection.send_msg("terminated")
            if msg[0] == 1:  # if installed then restart
                restart()
        finally:
            os.chdir(current_cwd)
    else:
        connection.send_msg("0")  # code 2: executing analysis
        connection.send_msg("not implemented yet")


# sniffer monitoring TCP packets and classified it by ports during x temp(s)
# and return dict(port:([input],[output]))
def sniffer(temp):
    import pcap
    # pc will capture network traffic
    result = dict()
    init_time = time.time()
    my_ip = Environment().private_ip
    pc = pcap.pcap(name=Environment().default_adapter)
    # as long as there are new packets
    for ts, pkt in pc:  # timestamp , packet
        # check time passed
        if time.time() - init_time >= temp:
            return result
            break
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data  # now data is ip
        if ip.__class__ == dpkt.ip.IP:
            # source IP address and Destination address
            ip1, ip2 = map(socket.inet_ntoa, [ip.src, ip.dst])
            # is the protocol TCP? (tcp has ports)
            if ip.p == socket.IPPROTO_TCP:  # TCP traffic
                I7 = ip.data
                # source IP port and Destination port
                sport, dport = [I7.sport, I7.dport]
                if len(I7.data) > 0:
                    # from my ip
                    if ip1 in my_ip:
                        if sport in result.keys():
                            (result[sport][1]).append(len(I7.data))
                        else:
                            result[sport] = ([], [len(I7.data)])
                    # to my ip
                    elif ip2 in my_ip:
                        if dport in result.keys():
                            (result[dport][0]).append(len(I7.data))
                        else:
                            result[dport] = ([len(I7.data)], [])


# retrieve_in_background do the task in background
def retrieve_in_background():
    data = sniffer(Environment().time_retrieve_network_sniffer)
    with open(Environment().path_streams + '/data.json', 'w') as fp:
        json.dump(data, fp, sort_keys=True, indent=4)
    return


# watch_traffic monitoring iface selected pacakges
def watch_traffic(connection: Connection):
    res, adapters = get_adapters()
    connection.send_msg("Interfaces -->\n" + res)
    import pcap
    try:
        # pc will capture network traffic
        pc = pcap.pcap(name=adapters[int(connection.recv_msg())])
        # as long as there are new packets
        time_s = time.time()
        while time.time() - time_s <=2: pass
        if pc.stats()[0]==0:
            connection.send_msg("1")
            connection.send_msg("no data found")
        else:
            connection.send_msg("0")
            for ts, pkt in pc:  # timestamp , packet
                if connection.recv_msg() != "continue":
                    break  # exit
                eth = dpkt.ethernet.Ethernet(pkt)
                ip = eth.data  # now data is ip
                if ip.__class__ == dpkt.ip.IP:
                    # source IP address and Destination address
                    ip1, ip2 = map(socket.inet_ntoa, [ip.src, ip.dst])
                    # is the protocol TCP? (tcp has ports)
                    if ip.p == socket.IPPROTO_TCP:  # only listen to TCP traffic (monitoring ports)
                        I7 = ip.data
                        # source IP port and Destination port
                        sport, dport = [I7.sport, I7.dport]
                        if len(I7.data) > 0:
                            connection.send_msg("From: " + str(ip1)+":"+str(sport) + " to: " + str(ip2)+":"+str(dport) + " length: " + str(len(I7.data)))
                        else:
                            connection.send_msg("alive")
                    else:
                        connection.send_msg("alive")
                else:
                    connection.send_msg("alive")
    except:
        connection.send_msg("Something went wrong during capture this device")
        connection.send_msg("terminated")
    finish = connection.recv_msg()
    while finish!= "finish": finish = connection.recv_msg()
    connection.send_msg("finish")


def get_adapters():
    if Environment().os == "Windows":
        from audit.windows.network import get_adapters as windows_adapters
        return windows_adapters()
    elif Environment().os == "Linux":
        from audit.linux.network import get_adapters as linux_adapters
        return linux_adapters()
    elif Environment().os == "Darwin":
        from audit.darwin.network import get_adapters as darwin_adapters
        return darwin_adapters()
    else:
        raise Exception("platform not supported")