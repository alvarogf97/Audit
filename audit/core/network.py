import json
import multiprocessing
import os
import socket
import time
import warnings
from datetime import datetime
from multiprocessing import Queue
import psutil
import dpkt
from audit.core.environment import Environment


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


def network_analysis(processes_active, new: bool):
    result = dict()
    result["status"] = True

    if "sniffer" in processes_active.keys():
        result["code"] = 0
        queue = processes_active["sniffer"][2]
        result["data"] = queue.get()
    elif not os.path.isfile(Environment().path_streams + "/data.json") or new:
        current_cwd = os.getcwd()
        try:
            import pcap
            os.chdir(Environment().base_path)
            queue = multiprocessing.Queue()
            background_sniffer = multiprocessing.Process(target=get_calibrate_file, args=(queue,))
            background_sniffer.start()
            processes_active["sniffer"] = (background_sniffer, time.time(), queue)
            result["data"] = "collecting information"
            result["code"] = 0
        except Exception as e:
            warnings.warn(str(e))
            result["code"] = 1
            if "installer" in processes_active.keys():
                # communicate with subprocess
                queue = processes_active["installer"][2]
                queue_msg = queue.get()
                if queue_msg == "fail":
                    processes_active["installer"][0].terminate()
                    result["code"] = -1
                result["installer"] = queue_msg
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
        result["code"] = 2
        result["data"] = dict()
        sniffer_data = sniffer(Environment().time_retrieve_network_sniffer)
        result["data"]["input"] = NetworkMeasure.list_to_json(sniffer_data["input"])
        result["data"]["output"] = NetworkMeasure.list_to_json(sniffer_data["output"])
        #TODO
        # dos listas de input y output como regresion estadistica (predecir evolucion)
        # analisis de las medidas con el fichero data para comprobar anomalias

    return result


def sniffer(temp):
    import pcap
    # pc will capture network traffic
    result = dict()
    result["input"] = []
    result["output"] = []
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
                pck_info = ip.data
                # print(ip.__bytes__)
                # source IP port and Destination port
                sport, dport = [pck_info.sport, pck_info.dport]
                if len(pck_info.data) > 0:
                    # from my ip
                    if ip1 in my_ip:
                        measure = NetworkMeasure(port=sport, size=len(pck_info),
                                                 timestamp=ts,
                                                 is_input=False)
                        result["output"].append(measure)
                    # to my ip
                    elif ip2 in my_ip:
                        measure = NetworkMeasure(port=dport, size=len(pck_info),
                                                 timestamp=ts,
                                                 is_input=True)
                        result["input"].append(measure)


def get_calibrate_file(queue: Queue):
    result = dict()
    queue.put("collecting packets data")
    data = sniffer(Environment().time_retrieve_network_sniffer)
    queue.put("packet data collect successfully")
    result["input"] = NetworkMeasure.list_to_json(data["input"])
    result["output"] = NetworkMeasure.list_to_json(data["output"])
    with open(Environment().path_streams + '/data.json', 'w') as fp:
        json.dump(result, fp, sort_keys=True, indent=4)
    queue.put("data file saved as \"data.json\"")
    queue.put("generating neuronal network")
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


class NetworkMeasure:

    def __init__(self, port, size, timestamp, is_input):
        self.port = port
        self.size = size
        self.timestamp = timestamp
        self.hour = str(datetime.utcfromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S'))
        self.is_input = is_input

    def to_json(self):
        result = dict()
        result["port"] = self.port
        result["size"] = self.size
        result["timestamp"] = self.timestamp
        result["hour"] = str(self.hour)
        result["is_input"] = self.is_input
        return result

    @staticmethod
    def list_to_json(measure_list):
        result = []
        for measure in measure_list:
            result.append(measure.to_json())
        return result

    @staticmethod
    def load_from_json(json_file):
        result = dict()
        result["input"] = []
        result["output"] = []
        with open(json_file, "r") as f:
            json_buffer = json.loads(f.read())
            for json_measure_input in json_buffer["input"]:
                result["input"].append(NetworkMeasure(port=json_measure_input["port"],
                                                        size=json_measure_input["size"],
                                                        timestamp=json_measure_input["timestamp"],
                                                        is_input=json_measure_input["is_input"]))
            for json_measure_output in json_buffer["output"]:
                result["output"].append(NetworkMeasure(port=json_measure_output["port"],
                                                        size=json_measure_output["size"],
                                                        timestamp=json_measure_output["timestamp"],
                                                        is_input=json_measure_output["is_input"]))
        return result
