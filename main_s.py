from client import Client
from server import Server
from pdm import PDMServer


def main():
    ip = "localhost"
    port = 65432
    wmodp = '15'
    client_id = 'ALICE'

    server = Server(ip, port, wmodp, client_id)

    pdms = PDMServer(server)

    pdms.run()


if __name__ == '__main__':
    main()
