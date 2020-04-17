from socket import *


class Client:

    # Ip: IP to connect to
    # port: port to connect to
    # password: client password for server
    # wmodp: 2^W mod p
    # c_id: Client id
    def __init__(self, ip, port, password, wmodp, c_id):
        self.ip = ip
        self.port = port
        self.password = password
        self.wmodp = wmodp
        self.id = c_id

    def connect(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.ip, self.port))

        return sock

