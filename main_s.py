from server import Server
from dmv import DMVServer
from pdm import PDMServer

import time

def main():
    ip = "localhost"
    port = 65432
    wmodp = str((2**15) % 17)
    client_id = 'ALICE'
    iv = b'0000000000000000'

    num_iter = 100

    # Only used in the PDM Server
    p = '17'

    server = Server(ip, port, wmodp, client_id, iv, p)

    dmvs = DMVServer(server, False)

    start = time.time()
    for i in range(0, num_iter):
        dmvs.run()
        print(i)
    end = time.time()

    print("DMV AVG time: ", (end - start) / num_iter)

    pdms = PDMServer(server, False)

    start = time.time()
    for i in range(0, num_iter):
        pdms.run()
        print(i)
    end = time.time()

    print("PDM AVG time: ", (end - start) / num_iter)


if __name__ == '__main__':
    main()
