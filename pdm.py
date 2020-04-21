from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class PDMServer:
    def __init__(self, server):
        self.server = server

    def run(self):
        print("                 ------- Starting up Server -------")
        conn, addr = self.server.run_server()

        print("                 ------- Connecting Client --------")

        print("                 ------- Initialization -----------")

        with open("client_pub.pem", "r") as f:
            key = f.read()

        key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
        self.server.set_client_pub_key(key)

        print("-------- Beginning Augmented PDM with Server Break-in Protection ----------")
        print("            |                                       |")
        print("            |        Diffie Hellman Exchange        |")
        print("            |<_____________________________________>|")
        print("            |                                       |")
        print("            |                                       |")

        d1, s_dh_pub = self.server.begin_diffie_hellman()

        # TODO Fix not being able to send full dh_pub_key
        self.server.send_dh_pub_key(conn, self.server.client_rsa_pub_key, str(s_dh_pub).encode())

        server_received_server_dh_pub = self.server.receive_client_dh_pub_key(conn)
        server_received_server_dh_pub = int(server_received_server_dh_pub.decode())

        self.server.set_shared_key(str(d1.gen_shared_key(server_received_server_dh_pub)).encode())

        print("            |           K[ 2^a mod p, p]            |")
        print("            |______________________________________>|")
        print("            |                                       |")

        amodp_and_p = self.server.receive_amodp_and_p(conn)

        print("            |             K[ 2^b mod p]             |")
        print("            |<______________________________________|")
        print("            |                                       |")

        # TODO Generate 2^b mod p
        bmodp = b'10'

        self.server.send_bmodp(conn, bmodp)

        print("            |      hash(2^ab mod p, 2^Wb mod p)     |")
        print("            |<______________________________________|")
        print("            |                                       |")



        print("            |      hash(2^ab mod p, 2^Wa mod p)     |")
        print("            |______________________________________>|")
        print("            |                                       |")


class PDMClient:
    def __init__(self, client):
        self.client = client

    def run(self):
        sock = self.client.connect()
        d2, c_dh_pub = self.client.begin_diffie_hellman()

        with open("server_pub.pem", "r") as f:
            key = f.read()

        key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
        self.client.set_server_pub_key(key)

        client_received_server_dh_pub = self.client.receive_server_dh_pub(sock)

        client_received_server_dh_pub = int(client_received_server_dh_pub.decode())
        self.client.send_dh_pub_key(sock, self.client.server_rsa_pub_key, str(c_dh_pub).encode())

        self.client.set_shared_key(str(d2.gen_shared_key(client_received_server_dh_pub)).encode())

        self.client.send_amodp_and_p(sock)

        # TODO Generate 2^b mod p
        received_bmodp = self.client.receive_bmodp(sock)

