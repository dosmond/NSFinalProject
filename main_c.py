from client import Client
from pdm import PDMClient


def main():
    ip = "localhost"
    port = 65432
    w = '15'
    client_id = 'ALICE'
    a = '16'
    p = '17'
    iv = b'0000000000000000'

    client = Client(ip, port, a, w, p, client_id, iv)

    pdmc = PDMClient(client)

    pdmc.run()


if __name__ == '__main__':
    main()
