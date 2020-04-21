from client import Client
from pdm import PDMClient


def main():
    ip = "localhost"
    port = 65432
    wmodp = '15'
    client_id = 'ALICE'
    amodp = '16'
    p = '5'

    client = Client(ip, port, amodp, wmodp, p, client_id)

    pdmc = PDMClient(client)

    pdmc.run()


if __name__ == '__main__':
    main()
