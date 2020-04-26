from client import Client
from dmv import DMVClient
from pdm import PDMClient


def main():
    ip = "localhost"
    port = 65432
    w = '15'
    client_id = 'ALICE'
    a = '16'
    p = '17'
    iv = b'0000000000000000'

    num_iter = 100

    client = Client(ip, port, a, w, p, client_id, iv)

    dmvc = DMVClient(client)

    for i in range(0, num_iter):
        dmvc.run()


    pdmc = PDMClient(client)

    for i in range(0, num_iter):
        pdmc.run()


if __name__ == '__main__':
    main()
