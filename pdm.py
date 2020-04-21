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
        print(len(str(s_dh_pub)))

        # TODO Fix not being able to send full dh_pub_key
        self.server.send_dh_pub_key(conn, self.server.client_rsa_pub_key, str(s_dh_pub).encode())

        server_received_server_dh_pub = self.server.receive_client_dh_pub_key(conn)

        self.server.set_shared_key(d1.gen_shared_key(server_received_server_dh_pub))

        if self.server.shared_key != self.client.shared_key:
            print("Diffie Hellman failed! Shared Keys are not equal")
            exit(0)

        print("            |           K[ 2^a mod p, p]            |")
        print("            |______________________________________>|")
        print("            |                                       |")

        amodp_and_p = self.server.receive_amodp_and_p(conn)

        if amodp_and_p != self.client.amodp + self.client.p:
            print("First message sent incorrectly! Try again")
            exit(0)

        print("            |             K[ 2^b mod p]             |")
        print("            |<______________________________________|")
        print("            |                                       |")

        # TODO Generate 2^b mod p
        bmodp = '10'

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

        self.client.send_dh_pub_key(sock, self.client.server_rsa_pub_key, c_dh_pub)

        self.client.set_shared_key(d2.gen_shared_key(client_received_server_dh_pub))

        if self.server.shared_key != self.client.shared_key:
            print("Diffie Hellman failed! Shared Keys are not equal")
            exit(0)

        self.client.send_amodp_and_p(sock)

        # TODO Generate 2^b mod p
        received_bmodp = self.client.receive_bmodp(sock)

