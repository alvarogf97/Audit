import json
import multiprocessing
import os
import socket
import time
import warnings
from multiprocessing import Queue
import psutil
import dpkt
from audit.core.environment import Environment


# get_ports_open_by_processes send ports which are open by processes
def get_ports_open_by_processes():
    result = dict()
    result["status"] = True
    process_ports = dict()
    for x in psutil.net_connections():
        try:
            if x.laddr.port in process_ports.keys() \
                    and not process_ports.get(x.laddr.port) is None \
                    and x.pid not in process_ports.get(x.laddr.port) \
                    and ({"pid": x.pid, "name": psutil.Process(x.pid).name()}) not in process_ports[x.laddr.port]:
                process_ports[x.laddr.port].append({"pid": x.pid, "name": psutil.Process(x.pid).name()})
            else:
                process_ports[x.laddr.port] = [{"pid": x.pid, "name": psutil.Process(x.pid).name()}]
        except Exception as e:
            warnings.warn(str(e))
    result["data"] = [{"port": port, "processes": processes} for port, processes in sorted(process_ports.items())]
    return result


# network_analysis inform about anomaly amount of data in packets
def network_analysis(processes_active, new: bool):
    result = dict()
    result["status"] = True

    if "sniffer" in processes_active.keys():
        result["data"] = "collecting information. Remaining time: " \
                            + str(max(Environment().time_retrieve_network_sniffer
                                      - (time.time() - processes_active["sniffer"][1]), 0)) \
                            + "s"
    elif not os.path.isfile(Environment().path_streams + "/data.json") or new:
        current_cwd = os.getcwd()
        try:
            import pcap
            os.chdir(Environment().base_path)
            queue = multiprocessing.Queue()
            sniffer = multiprocessing.Process(target=retrieve_in_background, args=(queue,))
            sniffer.start()
            processes_active["sniffer"] = (sniffer, time.time(), queue)
            result["data"] = "collecting information. Remaining time:: " \
                                + str(max(Environment().time_analysis_network
                                          + Environment().time_retrieve_network_sniffer
                                          - (time.time() - processes_active["sniffer"][1]), 0)) \
                                + "s"
        except Exception as e:
            warnings.warn(str(e))
            if "installer" in processes_active.keys():
                # communicate with subprocess
                queue = processes_active["vulners"][2]
                queue_msg = queue.get()
                if queue_msg == "fail":
                    processes_active["vulners"][1].terminate()
                result["data"] = queue_msg
            else:
                # install pcap
                queue = multiprocessing.Queue()
                installer = multiprocessing.Process(target=Environment().packetManager.install_package,
                                                    args=(queue, "pcap"))
                installer.start()
                processes_active["installer"] = (installer, time.time(), queue)
                result["data"] = "start installation"
        finally:
            os.chdir(current_cwd)
    else:
        result["data"] = "not implemented yet"

    return result


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
def retrieve_in_background(queue: Queue):
    data = sniffer(Environment().time_retrieve_network_sniffer)
    with open(Environment().path_streams + '/data.json', 'w') as fp:
        json.dump(data, fp, sort_keys=True, indent=4)
    return


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
