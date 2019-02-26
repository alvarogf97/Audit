import yara
import os
import psutil
import time
import warnings
from audit.core.core import delete_folder
from audit.core.environment import Environment
from git import Repo
from audit.core.file_system_manager import FileSystemManager


class ScanManager:

    ################################################################
    #    SCAN return structure:                                    #
    #       dict<String(process name), list(yara rules name)>      #
    ################################################################

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
        self.whitelisted_routes = ScanManager.read_whitelist(Environment().path_streams + "/whitelisted_routes.txt")
        self.whitelisted_processes = ScanManager.read_whitelist(Environment().path_streams +
                                                                "/whitelisted_processes.txt")
        self.rules = yara.load(Environment().path_streams + "/malware_compiled_rules")

    @staticmethod
    def fold_dict(dict_a, dict_b):
        result_dict = dict(dict_a)
        for key, value in dict_b.items():
            if key in result_dict.keys():
                result_dict[key] = list(set().union(result_dict[key], value))
            else:
                result_dict[key] = value
        return result_dict

    @staticmethod
    def read_whitelist(filename):
        whitelist = []
        with open(filename, "r") as f:
            for line in f.readline():
                whitelist.append(line)
        return whitelist

    @staticmethod
    def add_route_exception(route):
        ScanManager.add_to_whitelist(Environment().path_streams + "whitelisted_routes.txt", route)

    @staticmethod
    def add_process_exception(process):
        ScanManager.add_to_whitelist(Environment().path_streams + "whitelisted_processes.txt", process)

    @staticmethod
    def add_to_whitelist(filename, string):
        with open(filename, "a") as f:
            f.write(string + "\n")

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
        ScanManager.get_rules_from_git()
        all_yara_files = ScanManager.list_yara_files()
        all_yara_filtered_1 = ScanManager.remove_incompatible_imports(all_yara_files)
        all_yara_filtered_2 = ScanManager.fix_duplicated_rules(all_yara_filtered_1)
        ScanManager.merge_rules(all_yara_filtered_2)
        print(Environment().path_streams + '/malware_rules.yar')
        cwd = os.getcwd()
        os.chdir(Environment().path_streams)
        rules = yara.compile(filepath='malware_rules.yar')
        rules.save('malware_compiled_rules')
        os.chdir(cwd)
        os.remove(Environment().path_streams + '/malware_rules.yar')
        os.chdir(Environment().path_download_files)
        delete_folder("YARA")
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
        analysis_results = dict()
        try:
            matches = self.clean_matches(self.rules.match(pid=process.pid))
            if len(matches) > 0:
                analysis_results[process.name()] = matches
        except Exception as e:
            warnings.warn(str(e))
        return analysis_results

    def check_exec_processes(self, timeout=time_processes_analysis, queue=None):
        init_time = time.time()
        analysis_results = dict()
        for process in psutil.process_iter():
            analysis_results = ScanManager.fold_dict(analysis_results, self.check_process(process))
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
        analysis_results = dict()
        try:
            with open(filename, "rb") as current_file:
                matches = self.clean_matches(self.rules.match(data=current_file.read()))
                if len(matches) > 0:
                    analysis_results[filename] = matches
        except Exception as e:
            warnings.warn(str(e))
        return analysis_results

    def check_dir(self, name, queue=None, files_checked=0, total_files=-1):
        analysis_results = dict()
        if total_files == -1:
            total_files = FileSystemManager.count_dir_files(name)
            print(total_files)
        if not os.path.isdir(name):
            analysis_results = ScanManager.fold_dict(analysis_results, self.check_file(name))
            files_checked = files_checked + 1
            if queue:
                queue.put("Executing analysis: " + str(min(round((files_checked * 100 / total_files), 1), 100)) + "%")
        else:
            for item in os.listdir(name):
                new_results, new_files_checked = self.check_dir((name + '/' + item) if name != '/' else '/' + item,
                                                                queue,
                                                                files_checked, total_files)
                analysis_results = ScanManager.fold_dict(analysis_results, new_results)
                files_checked = new_files_checked
        return analysis_results, files_checked
