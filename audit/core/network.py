import json
import multiprocessing
import os
import socket
import time
import warnings
import psutil
import dpkt
import numpy as np
import lsanomaly
from datetime import datetime
from multiprocessing import Queue
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


def get_process_name_by_port(port):
    for x in psutil.net_connections():
        if x.laddr.port == port:
            return psutil.Process(x.pid).name()
    return ""


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
            result["code"] = 0
            if "installer" in processes_active.keys():
                queue = processes_active["installer"][2]
                queue_msg = queue.get()
                if queue_msg == "fail":
                    processes_active["installer"][0].terminate()
                    result["code"] = -1
                result["data"] = queue_msg
            else:
                queue = multiprocessing.Queue()
                installer = multiprocessing.Process(target=Environment().packetManager.install_package,
                                                    args=(queue, "pcap"))
                installer.start()
                processes_active["installer"] = (installer, time.time(), queue)
                result["data"] = "start installation"
        finally:
            os.chdir(current_cwd)
    else:
        if Environment().networkNeuralClassifierManager is None:
            Environment().networkNeuralClassifierManager = \
                NetworkNeuralClassifierManager(Environment().path_streams + '/data.json')
        result["data"] = dict()
        sniffer_data = sniffer(Environment().time_analysis_network)
        if len(sniffer_data["input"]) > 1 and len(sniffer_data["output"]) > 1:
            result["code"] = 1
            result["data"]["input"] = NetworkMeasure.list_to_json(sniffer_data["input"])
            result["data"]["output"] = NetworkMeasure.list_to_json(sniffer_data["output"])
            result["data"]["abnormal_input"] = NetworkMeasure.list_to_json(Environment().
                                                                      networkNeuralClassifierManager.
                                                                      check_measure_list(sniffer_data["input"]))
            result["data"]["abnormal_output"] = NetworkMeasure.list_to_json(Environment().
                                                                      networkNeuralClassifierManager.
                                                                      check_measure_list(sniffer_data["input"]))
        else:
            result["code"] = 2
    return result


def sniffer(temp, queue=None):
    import pcap
    result = dict()
    result["input"] = []
    result["output"] = []
    init_time = time.time()
    my_ip = Environment().private_ip
    pc = pcap.pcap(name=Environment().default_adapter)
    for ts, pkt in pc:
        if queue:
            queue.put("Recollecting data: " + str(round(((time.time() - init_time)*100 / temp), 1)) + "%")
        if time.time() - init_time >= temp:
            return result
            break
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        if ip.__class__ == dpkt.ip.IP:
            ip1, ip2 = map(socket.inet_ntoa, [ip.src, ip.dst])
            if ip.p == socket.IPPROTO_TCP:
                pck_info = ip.data
                sport, dport = [pck_info.sport, pck_info.dport]
                if len(pck_info.data) > 0:
                    if ip1 in my_ip:
                        measure = NetworkMeasure(port=sport, size=len(pck_info),
                                                 timestamp=ts,
                                                 is_input=False)
                        result["output"].append(measure)
                    elif ip2 in my_ip:
                        measure = NetworkMeasure(port=dport, size=len(pck_info),
                                                 timestamp=ts,
                                                 is_input=True)
                        result["input"].append(measure)


def get_calibrate_file(queue: Queue):
    result = dict()
    queue.put("collecting packets data")
    data = sniffer(Environment().time_retrieve_network_sniffer, queue)
    queue.put("packet data collect successfully")
    result["input"] = NetworkMeasure.list_to_array_data(data["input"])
    result["output"] = NetworkMeasure.list_to_array_data(data["output"])
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


class NetworkNeuralClassifierManager:

    def __init__(self, path_file_data):
        with open(path_file_data, "r") as f:
            self.data_dict = json.loads(f.read())
        self.input_classifier = self.generate_neural_classifier(data_list=self.data_dict["input"])
        self.output_classifier = self.generate_neural_classifier(data_list=self.data_dict["output"])

    @staticmethod
    def generate_neural_classifier(data_list):
        x_train = np.array(data_list)
        clf = lsanomaly.LSAnomaly()
        clf.fit(x_train)
        return clf

    def check_measure_list(self, measure_list):
        result = []
        np_array = np.array(NetworkMeasure.list_to_array_data(measure_list))
        anomalies = [self.input_classifier.predict(np_array), self.output_classifier.predict(np_array)]
        for x in range(0, len(anomalies)):
            if anomalies[x] == 'anomaly':
                result.append(measure_list[x])
        return result

    def add_exception(self, measure):
        result = dict()
        measure = NetworkMeasure.get_from_json(measure)
        if measure.is_input:
            self.data_dict["input"].append(measure.to_array_data())
            self.input_classifier = self.generate_neural_classifier(self.data_dict["input"])
        else:
            self.data_dict["output"].append(measure.to_array_data())
            self.output_classifier = self.generate_neural_classifier(self.data_dict["output"])
        result["status"] = True
        result["data"] = ""
        return result


class NetworkMeasure:

    def __init__(self, port, size, timestamp, is_input):
        self.port = port
        self.process_name = get_process_name_by_port(port)
        self.size = size
        self.timestamp = timestamp
        self.hour = str(datetime.utcfromtimestamp(self.timestamp).strftime('%H:%M:%S'))
        self.seconds = sum(x * int(t) for x, t in zip([3600, 60, 1], self.hour.split(":")))
        self.is_input = is_input

    def to_json(self):
        result = dict()
        result["port"] = self.port
        result["size"] = self.size
        result["timestamp"] = self.timestamp
        result["hour"] = str(self.hour)
        result["is_input"] = self.is_input
        result["process_name"] = self.process_name
        return result

    def to_array_data(self):
        return [self.port, self.size, self.seconds]

    @staticmethod
    def list_to_array_data(measure_list):
        result = []
        for measure in measure_list:
            measure_data = measure.to_array_data()
            if measure_data not in result:
                result.append(measure_data)
        return result

    @staticmethod
    def list_to_json(measure_list):
        result = []
        for measure in measure_list:
            result.append(measure.to_json())
        return result

    @staticmethod
    def get_from_json(json_measure):
        return NetworkMeasure(port=json_measure["port"], size=json_measure["size"],
                              timestamp=json_measure["timestamp"], is_input=json_measure["is_input"])
