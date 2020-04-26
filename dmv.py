from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class DMVServer:
    def __init__(self, server, debug):
        self.server = server
        self.DEBUG = debug

    def run(self):
        self.dprint("                 ------- Starting up Server -------")
        conn, addr = self.server.run_server()

        self.dprint("                 ------- Connecting Client --------")

        self.dprint("                 ------- Initialization -----------")

        with open("client_pub.pem", "r") as f:
            key = f.read()

        key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
        self.server.set_client_pub_key(key)

        self.dprint("-------- Beginning Augmented PDM with Server Break-in Protection ----------")
        self.dprint("            |                                       |")
        self.dprint("            |      RSA-Diffie Hellman Exchange      |")
        self.dprint("            |<_____________________________________>|")
        self.dprint("            |                                       |")
        self.dprint("            |                                       |")

        d1, s_dh_pub = self.server.begin_diffie_hellman()

        self.server.send_dh_pub_key(conn, self.server.client_rsa_pub_key, str(s_dh_pub).encode())

        server_received_server_dh_pub = int(self.server.receive_client_dh_pub_key(conn))

        self.server.set_shared_key(str(d1.gen_shared_key(server_received_server_dh_pub)).encode())

        self.dprint("            |           K[ 2^a mod p, p]            |")
        self.dprint("            |______________________________________>|")
        self.dprint("            |                                       |")

        amodp_and_p = self.server.receive_amodp_and_p(conn)

        amodp, p = self.server.parse_amod_p_and_p(amodp_and_p)

        self.dprint("            |             K[ 2^b mod p]             |")
        self.dprint("            |<______________________________________|")
        self.dprint("            |                                       |")

        # TODO Generate 2^b mod p
        b = 10
        bmodp = str((2**b) % p).encode()

        abmodp = str((amodp**b) % p)
        wbmodp = str((int(self.server.wmodp)**b) % p)

        self.server.send_bmodp(conn, bmodp)

        first_hash = self.server.gen_hash((abmodp + wbmodp).encode())
        second_hash = self.server.gen_hash((wbmodp + abmodp).encode())

        self.dprint("            |      K[hash(2^ab mod p, 2^Wb mod p)]  |")
        self.dprint("            |<______________________________________|")
        self.dprint("            |                                       |")
        self.server.send_first_hash(conn, first_hash)
        self.dprint("            |     K[hash(2^bW mod p, 2^ab mod p)]   |")
        self.dprint("            |______________________________________>|")
        self.dprint("            |                                       |")
        r_second_hash = self.server.receive_second_hash(conn)

        if r_second_hash != second_hash:
            print("Client not validated! Closing Connection!")
            exit(0)

        self.dprint("                    ------- Complete ------")

    def dprint(self, msg):
        if self.DEBUG:
            print(msg)


class DMVClient:
    def __init__(self, client):
        self.client = client

    def run(self):
        sock = self.client.connect()
        d2, c_dh_pub = self.client.begin_diffie_hellman()

        with open("server_pub.pem", "r") as f:
            key = f.read()

        # Load in Server's public key
        key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
        self.client.set_server_pub_key(key)

        # Receive server Diffie Hellman pub key
        client_received_server_dh_pub = int(self.client.receive_server_dh_pub(sock))

        # Send Client Diffie Hellman pub key to server
        self.client.send_dh_pub_key(sock, self.client.server_rsa_pub_key, str(c_dh_pub).encode())

        # Generate the shared key and set the client instance variable
        self.client.set_shared_key(str(d2.gen_shared_key(client_received_server_dh_pub)).encode())

        # Send K[ 2^a mod p, p ]
        self.client.send_amodp_and_p(sock)

        # Receive K[ 2^b mod p ]
        bmodp = self.client.receive_bmodp(sock)

        abmodp = str((bmodp**int(self.client.a)) % int(self.client.p))
        wbmodp = str((bmodp**int(self.client.w)) % int(self.client.p))

        first_hash = self.client.gen_hash((abmodp + wbmodp).encode())
        second_hash = self.client.gen_hash((wbmodp + abmodp).encode())

        # Receive hash( 2^ab mod p, 2^Wb mod p)
        r_first_hash = self.client.receive_first_hash(sock)

        if r_first_hash != first_hash:
            print("Server was not authenticated! Closing connection!")
            exit(0)

        # Send hash'(2^bW mod p, 2^ab mod p)
        self.client.send_second_hash(sock, second_hash)


