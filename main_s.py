from server import Server
from pdm import PDMServer


def main():
    ip = "localhost"
    port = 65432
    wmodp = str((2**15) % 17)
    client_id = 'ALICE'
    iv = b'0000000000000000'

    server = Server(ip, port, wmodp, client_id, iv)

    pdms = PDMServer(server)

    pdms.run()


if __name__ == '__main__':
    main()
