import socket
import ssl
import struct
from audit.core.environment import Environment


class Connection:

    def __init__(self,port: int, path_certs=Environment().path_certs):
        self.sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                    keyfile=path_certs + "/trusted_server.pem",
                                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                                    certfile=path_certs + "/trusted_server.crt",
                                    ca_certs=path_certs + "/CA.crt",
                                    server_side=True,
                                    cert_reqs=ssl.CERT_REQUIRED)
        server_address = (Environment().private_ip, port)
        self.sock.bind(server_address)
        self.sock.listen(1)
        self.connection = None
        self.client_address = None

    def accept(self):
        self.connection, self.client_address = self.sock.accept()

    def close_connection(self):
        self.connection.close()

    def send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = msg.encode('utf-8')
        msg = struct.pack('>I', len(msg)) + msg
        self.connection.sendall(msg)

    def send_bytes(self, bytes):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(bytes)) + bytes
        self.connection.sendall(msg)

    def recv_msg(self):
        # Read message length and unpack it into an integer
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return (self.recvall(msglen)).decode('utf-8')

    def recv_msg_bytes(self):
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return self.recvall(msglen)

    def recvall(self, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = ''.encode('utf-8')
        while len(data) < n:
            packet = self.connection.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def get_client_address(self):
        return self.client_address

    def has_connection(self):
        if self.connection is None:
            return False
        else:
            return True
