import os
import warnings
from audit.core.connection import Connection
from audit.core.environment import Environment


# GET:
# send filename
# send ok(if file exists, file not found in other case)
# send file
# send terminate to conclude the operation
def get(connection: Connection, command: str):

    splitted = command.split("$")

    try:
        path_files = os.getcwd()

        if len(splitted) > 1:
            # path file / get the file to current machine path_download_files
            filename = splitted[1]
            connection.send_msg("1")
            send_file(connection, filename)
            print(filename + " -> has been sended")

        else:
            # gets all files from the current directory to current machine path_download_files
            files = [f for f in os.listdir(path_files) if os.path.isfile(os.path.join(path_files, f))]
            connection.send_msg(str(len(files)))
            for file in files:
                send_file(connection, file)
                print(file + " -> has been sended")

    except Exception as e:
        warnings.warn(str(e))
        connection.send_msg("file not found")


def send_file(connection, filename):

    # first send filename
    connection.send_msg(filename)

    # then send file
    path = os.getcwd()
    file = open(path+"/"+filename, 'rb')
    connection.send_msg("ok")

    datagram = file.read(1024)
    while datagram:
        connection.send_bytes(datagram)
        datagram = file.read(1024)

    # close file and send terminated
    file.close()
    connection.send_bytes("terminated".encode('utf-8'))


# SEND:
# get confirmation that path exists(only third case)
# get number of files(only third case)
# get filename
# get ok(if file exists, file not found in other case)
# get file
# get terminate to conclude the operation
def send(connection, command):

    splitted = command.split("$")

    if len(splitted) > 3:
        # filename,file_path,path_to_save_file
        filename = connection.recv_msg()
        filepath = splitted[3]
        get_file(connection, filename, filepath)
        print("received-> " + filename)

    elif len(splitted) > 2:
        # filename, path_download_files
        filename = connection.recv_msg()
        get_file(connection, filename)
        print("received-> " + filename)

    else:
        # allfiles, path_download_files
        confirmation = connection.recv_msg()
        if not confirmation.startswith("ok"):
            raise IOError("path not found")
        files = int(connection.recv_msg())
        files_processed = 0
        while files_processed < files:
            filename = connection.recv_msg()
            get_file(connection, filename)
            print("received-> " + filename)
            files_processed += 1


def get_file(connection, filename, path=Environment().path_download_files):

    confirmation = connection.recv_msg()

    if not confirmation.startswith("ok"):
        raise IOError("file not found")

    current_file = open(path+"/"+filename, 'wb')
    finish = False

    datagram = connection.recv_msg_bytes()
    while not finish:
        current_file.write(datagram)
        datagram = connection.recv_msg_bytes()
        try:
            finish_flag = datagram.decode('utf-8')
            if finish_flag.startswith("terminated"):
                finish = True
        except Exception as e:
            warnings.warn(str(e))
            continue
    current_file.close()
