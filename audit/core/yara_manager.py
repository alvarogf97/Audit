import yara
import os
import psutil
import time
import warnings
import multiprocessing
import json
from abc import abstractmethod
from typing import Dict
from multiprocessing import Queue
from audit.core.environment import Environment
from git import Repo
from audit.core.file_system_manager import FileSystemManager


class YaraManager:

    # whitelisted_rules are list of rules which form part of another rules and could be false-positive#
    whitelisted_rules = ["Str_Win32_Wininet_Library",
                         "Str_Win32_Winsock2_Library",
                         "Str_Win32_Internet_API",
                         "Str_Win32_Http_API",
                         "rar_with_js",
                         "Insta11Code",
                         "Insta11",
                         "is__elf",
                         "SharedStrings",
                         "RSharedStrings",
                         "PM_Zip_with_js",
                         "JavaDropper", ]

    time_processes_analysis = 30

    def __init__(self):
        self.whitelisted_routes = YaraManager.read_whitelist(Environment().path_streams + "/whitelisted_routes.txt")
        self.whitelisted_processes = YaraManager.read_whitelist(Environment().path_streams +
                                                                "/whitelisted_processes.txt")
        cwd = os.getcwd()
        os.chdir(Environment().path_streams)
        self.rules = yara.load("malware_compiled_rules")
        os.chdir(cwd)
        self.last_msg = ""
        self.last_scan_type = 0

    @staticmethod
    def update_list(_list, list_item):
        for item in _list:
            if item == list_item:
                item.add_rules(list_item.yara_rules)

    @staticmethod
    def fold(infected_a, infected_b):
        infected_list = infected_a.copy()
        for infected in infected_b:
            if infected in infected_list:
                YaraManager.update_list(infected_list, infected)
            else:
                infected_list.append(infected)
        return infected_list

    @staticmethod
    def read_whitelist(filename):
        whitelist = []
        with open(filename, "r") as f:
            for line in f.readline():
                whitelist.append(line)
        return whitelist

    @staticmethod
    def add_route_exception(route):
        return YaraManager.add_to_whitelist(Environment().path_streams + "whitelisted_routes.txt", route)

    @staticmethod
    def add_process_exception(process):
        return YaraManager.add_to_whitelist(Environment().path_streams + "whitelisted_processes.txt", process)

    @staticmethod
    def add_to_whitelist(filename, string):
        result = dict()
        try:
            with open(filename, "a") as f:
                f.write(string + "\n")
                result["status"] = True
        except Exception as e:
            warnings.warn(str(e))
            result["status"] = False
        return result

    @staticmethod
    def get_rules_from_git():
        cwd = os.getcwd()
        os.chdir(Environment().path_download_files)
        os.mkdir("YARA")
        try:
            Repo.clone_from("https://github.com/Yara-Rules/rules", Environment().path_download_files + "/YARA")
        except Exception as e:
            warnings.warn(str(e))
        os.chdir(cwd)

    @staticmethod
    def list_yara_files():
        all_yara_files = []
        for root, directories, filenames in os.walk(Environment().path_download_files + "/YARA/malware"):
            filenames.sort()
            for file_name in filenames:
                rule_filename, rule_file_extension = os.path.splitext(file_name)
                if rule_file_extension == ".yar" or rule_file_extension == ".yara":
                    all_yara_files.append(os.path.join(root, file_name))
        return all_yara_files

    @staticmethod
    def remove_incompatible_imports(files):
        filtered_files = []
        for yara_file in files:
            with open(yara_file, 'r') as fd:
                yara_in_file = fd.read()
                if not (("import \"math\"" in yara_in_file) or ("import \"cuckoo\"" in yara_in_file) or (
                        "import \"hash\"" in yara_in_file) or ("imphash" in yara_in_file)):
                    filtered_files.append(yara_file)
        return filtered_files

    @staticmethod
    def fix_duplicated_rules(files):
        filtered_files = []
        first_elf = True
        to_delete = False
        for yara_file in files:
            with open(yara_file, 'r') as fd:
                yara_in_file = fd.readlines()
                for line in yara_in_file:
                    if line.strip() == "private rule is__elf {":
                        if first_elf:
                            first_elf = False
                        else:
                            to_delete = True
                    if not to_delete:
                        filtered_files.append(line)
                    if (not first_elf) and line.strip() == "}":
                        to_delete = False
                filtered_files.append("\n")
        return filtered_files

    @staticmethod
    def merge_rules(all_rules):
        with open(Environment().path_streams + "/malware_rules.yar", 'w') as fd:
            fd.write(''.join(all_rules))

    @staticmethod
    def update_yara_rules():
        YaraManager.get_rules_from_git()
        all_yara_files = YaraManager.list_yara_files()
        all_yara_filtered_1 = YaraManager.remove_incompatible_imports(all_yara_files)
        all_yara_filtered_2 = YaraManager.fix_duplicated_rules(all_yara_filtered_1)
        YaraManager.merge_rules(all_yara_filtered_2)
        print(Environment().path_streams + '/malware_rules.yar')
        cwd = os.getcwd()
        os.chdir(Environment().path_streams)
        rules = yara.compile(filepath='malware_rules.yar')
        rules.save('malware_compiled_rules')
        os.chdir(cwd)
        os.remove(Environment().path_streams + '/malware_rules.yar')
        os.chdir(Environment().path_download_files)
        try:
            FileSystemManager.delete_folder("YARA")
        except Exception as e:
            warnings.warn(str(e))
        os.chdir(cwd)

    def clean_matches(self, matches):
        filtered_matches = []
        for match in matches:
            if match.rule not in self.whitelisted_rules:
                filtered_matches.append(match)
        return filtered_matches

    ######################################################
    #                MEMORY PROCESS SCAN                 #
    ######################################################

    def check_process(self, process):
        analysis_results = []
        try:
            matches = self.clean_matches(self.rules.match(pid=process.pid))
            if len(matches) > 0:
                analysis_results.append(InfectedProcess(process, matches))
        except Exception as e:
            warnings.warn(str(e))
        return analysis_results

    def check_exec_processes(self, queue=None, timeout=time_processes_analysis):
        init_time = time.time()
        analysis_results = dict()
        for process in psutil.process_iter():
            analysis_results = YaraManager.fold(analysis_results, self.check_process(process))
            if queue:
                queue.put("Executing analysis: " + str(
                    min(round(((time.time() - init_time) * 100 / timeout), 1), 100)) + "%")
            if time.time() - init_time >= timeout:
                break
        return analysis_results

    ######################################################
    #                     FILES SCAN                     #
    ######################################################

    def check_file(self, filename):
        analysis_results = []
        try:
            with open(filename, "rb") as current_file:
                matches = self.clean_matches(self.rules.match(data=current_file.read()))
                if len(matches) > 0:
                    analysis_results.append(InfectedFile(filename, matches))
        except Exception as e:
            warnings.warn(str(e))
        return analysis_results

    def check_dir(self, name, queue=None, files_checked=0, total_files=-1):
        analysis_results = []
        if total_files == -1:
            total_files = FileSystemManager.count_dir_files(name)
            print(total_files)
        if not os.path.isdir(name):
            analysis_results = YaraManager.fold(analysis_results, self.check_file(name))
            files_checked = files_checked + 1
            if queue:
                queue.put("Executing analysis: " + str(min(round((files_checked * 100 / total_files), 1), 100)) + "%")
        else:
            for item in os.listdir(name):
                new_results, new_files_checked = self.check_dir((name + '/' + item) if name != '/' else '/' + item,
                                                                queue,
                                                                files_checked, total_files)
                analysis_results = YaraManager.fold(analysis_results, new_results)
                files_checked = new_files_checked
        return analysis_results, files_checked

    ######################################################
    #                          SCAN                      #
    ######################################################

    def background_scan(self, args, queue):
        if args["scan_type"] == 0:
            result = self.check_file(args["filename"])
        elif args["scan_type"] == 1:
            result = self.check_dir(args["directory"], queue)
        else:
            result = self.check_exec_processes(queue)
        result = Infected.list_to_json(result)
        with open(Environment().path_streams + '/yara_last_scan.json', 'w') as fp:
            json.dump(result, fp, sort_keys=True, indent=4)
        return

    def scan(self, args, processes_active):

        """
        :param processes_active: current active subprocess
        :param args = [
            "scan_type" : (0 for file, 1 for directory, 3 for memory process)
            "directory" : "" (dir_name if scan_type = 1)
            "filename" : "" (file_name if scan_type = 0)
        ]

        :return: Infected list
        """

        result = dict()
        if "yarascan" in processes_active.keys():
            # communicate with subprocess
            queue = processes_active["yarascan"][2]
            result["data"] = self.get_queue_msg(queue)
            result["status"] = False
        elif not os.path.isfile(Environment().path_streams + "/yara_last_scan.json"):
            queue = Queue()
            self.last_scan_type = args["scan_type"]
            yarascan = multiprocessing.Process(target=self.background_scan, args=(args, queue,))
            yarascan.start()
            processes_active["yarascan"] = (yarascan, time.time(), queue)
            result["data"] = "launch scanner"
            result["status"] = False
            self.last_msg = result
        else:
            if not isinstance(self.last_msg, Dict):
                with open(Environment().path_streams + "/yara_last_scan.json", "r") as f:
                    output = json.loads(f.read())
                result["data"] = output
                result["status"] = True
                result["scan_type"] = self.last_scan_type
                self.last_msg = output
                # delete file for next SCAN
                os.remove(Environment().path_streams + "/yara_last_scan.json")
            else:
                result["data"] = self.last_msg
                result["status"] = True
        return result

    def get_queue_msg(self, queue: Queue):
        try:
            last = queue.get(timeout=2)
            self.last_msg = last
        except Exception as e:
            warnings.warn(str(e))
            last = self.last_msg
        return last

    ######################################################
    #                        FACADE                      #
    ######################################################

    def yara_action(self, command, args, processes_active):
        if command.startswith("yarascan scan"):
            return self.scan(args, processes_active)
        elif command.startswith("yarascan process exception"):
            return YaraManager.add_process_exception(args["process"])
        elif command.startswith("yarascan route exception"):
            return YaraManager.add_process_exception(args["route"])


class Infected:

    def __init__(self, yara_rules):
        self.yara_rules = yara_rules

    def add_rules(self, rules):
        self.yara_rules = list(set().union(self.yara_rules, rules))

    @staticmethod
    def list_to_json(infected_list):
        result = []
        for infected in infected_list:
            result.append(infected.to_json())
        return result

    @staticmethod
    def serialize_yara_rules(yara_list):
        result = []
        for rule in yara_list:
            result.append(rule.rule)
        return result

    @abstractmethod
    def to_json(self):
        pass


class InfectedFile(Infected):

    def __init__(self, file, yara_rules):
        super().__init__(yara_rules)
        self.abs_path = file
        self.filename = FileSystemManager.path_leaf(file)
        self.file_route = FileSystemManager.base_path(file)
        self.size = FileSystemManager.get_file_size(file)

    def __eq__(self, other):
        result = False
        if isinstance(other, InfectedFile):
            result = self.abs_path == other.abs_path
        return result

    def to_json(self):
        result = dict()
        result["filename"] = self.filename
        result["file_route"] = self.file_route
        result["size"] = self.size
        result["rules"] = Infected.serialize_yara_rules(self.yara_rules)
        return result


class InfectedProcess(Infected):

    def __init__(self, process, yara_rules):
        super().__init__(yara_rules)
        self.name = process.name()
        self.pid = process.pid
        self.location = process.exe()

    def __eq__(self, other):
        result = False
        if isinstance(other, InfectedProcess):
            result = self.location == other.location
        return result

    def to_json(self):
        result = dict()
        result["name"] = self.name
        result["pid"] = self.pid
        result["location"] = self.location
        result["rules"] = Infected.serialize_yara_rules(self.yara_rules)
        return result
