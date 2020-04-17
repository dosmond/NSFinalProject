from socket import *


class Server:

    # ip: ip to host at
    # port: port to host on
    # wmodp: 2^W mod p
    # client_id: Client's identifier
    def __init__(self, ip, port, wmodp, client_id):
        self.ip = ip
        self.port = port
        self.wmodp = wmodp
        self.client_id = client_id

    def run_server(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.ip, self.port))
        sock.listen(1)

        conn, addr = sock.accept()

        return conn, addr
