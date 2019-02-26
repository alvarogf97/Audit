import codecs
import os
import subprocess
import sys
import warnings
import psutil
from audit.core.environment import Environment


def shell_command(command):
    with open(Environment().path_streams + "/stdout.txt", "wb") as stdout_file, \
            open(Environment().path_streams + "/stderr.txt", "wb") as stderr_file, \
            open(Environment().path_streams + "/stdin.txt", "wb") as stdin_file:
        handle = subprocess.Popen(command, shell=True,
                                  stdin=stdin_file,
                                  stdout=stdout_file,
                                  stderr=stderr_file)
        handle.wait()


def exec_command(command: str):
    result = dict()
    shell_command(command)
    stdout, stderr = communicate()
    if stdout == '' and stderr == '':
        # send that's right if there's no output
        result["status"] = True
        result["data"] = "execution successfully"
    elif stdout != '':
        # send output
        result["status"] = True
        result["data"] = stdout
    else:
        # send error if something happen
        result["status"] = False
        result["data"] = stderr
    return result


def communicate():
    stdout_file = codecs.open(Environment().path_streams + "/stdout.txt",
                              mode="rb", encoding=Environment().codec_type,
                              errors="replace")
    stderr_file = codecs.open(Environment().path_streams + "/stderr.txt",
                              mode="rb", encoding=Environment().codec_type,
                              errors="replace")
    stdout = stdout_file.read()
    stderr = stderr_file.read()
    stdout_file.close()
    stderr_file.close()
    return stdout, stderr


def cd(new_cwd: str):
    result = dict()
    try:
        os.chdir(new_cwd)
        result["data"] = os.getcwd()
        result["status"] = True
    except Exception as e:
        warnings.warn(str(e))
        result["data"] = "the directory: " + new_cwd + " doesn't exists"
        result["status"] = False
    return result


def get_processes():
    result = dict()
    result["satus"] = True
    process_list = []
    for process in psutil.process_iter():
        process_list.append({"pid": str(process.pid), "name": process.name()})
    result["data"] = process_list
    return result


def kill_process(pid: str):
    result = dict()
    try:
        pid = int(pid)
        process = psutil.Process(pid)
        process.kill()
        result["status"] = True
        result["data"] = "Killed successfully"
    except Exception as e:
        result["status"] = False
        result["data"] = "Cannot kill it!"
        warnings.warn(str(e))
    return result


# restart restart the system
def restart():
    os.execl(sys.executable, sys.executable, *sys.argv)


# check_active_processes() delete from de dict processes which have finished
def check_active_processes(process_active):
    revocation_list = []
    for process in process_active.keys():
        if not process_active[process][0].is_alive():
            revocation_list.append(process)
    for name in revocation_list:
        process_active[name][2].close()
        process_active.pop(name, None)  # Process is finish


def delete_folder(directory):
    if not os.path.isdir(directory):
        os.remove(directory)
    else:
        for item in os.listdir(directory):
            delete_folder((directory + '/' + item) if directory != '/' else '/' + item)
            os.rmdir(item)
    os.rmdir(directory)


def string_to_ascii(string):
    if string == '':
        return 0
    else:
        return float(''.join(str(ord(c)) for c in string))
