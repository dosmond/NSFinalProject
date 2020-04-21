from socket import *
import pyDH as d
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


class Client:
    # Ip: IP to connect to
    # port: port to connect to
    # password: client password for server
    # wmodp: 2^W mod p
    # c_id: Client id
    def __init__(self, ip, port, amodp, wmodp, p, c_id):
        self.ip = ip
        self.port = port
        self.wmodp = wmodp
        self.amodp = amodp
        self.p = p
        self.id = c_id

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        key_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )

        with open("client_pub.pem", 'w') as f:
            f.write(key_pem.decode())

        self.rsa_private_key = key
        self.rsa_pub_key = key.public_key()
        self.shared_key = None
        self.server_rsa_pub_key = None

    def connect(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.ip, self.port))

        return sock

    def set_server_pub_key(self, key):
        self.server_rsa_pub_key = key

    def begin_diffie_hellman(self):
        dh = d.DiffieHellman()
        public_key = dh.gen_public_key()
        return dh, public_key

    def gen_shared_key(self, dh, server_dh_key):
        return dh.gen_shared_key(server_dh_key)

    def encrypt_using_server_public(self, pub_key, msg):
        return pub_key.encrypt(msg, padding.PKCS1v15())

    def decrypt_using_private_key(self, ciphertext):
        return self.rsa_private_key.decrypt(ciphertext, padding.PKCS1v15)

    def receive_server_dh_pub(self, sock):
        res = sock.recv(4096)
        return self.decrypt_using_private_key(res)

    def send_dh_pub_key(self, conn, server_rsa_pub_key, dh_pub_key):
        encrypted_key = self.encrypt_using_server_public(server_rsa_pub_key, dh_pub_key)
        conn.sendall(encrypted_key)

    def set_shared_key(self, key):
        self.shared_key = key

    def send_amodp_and_p(self, sock):
        encrypted_msg = self.encrypt(self.amodp + self.p, self.shared_key, b'00000000')
        sock.sendall(encrypted_msg)

    def receive_bmodp(self, sock):
        res = sock.recv(4096)
        msg = self.decrypt(res, self.shared_key, b'00000000')
        return msg

    # CBC-AES Encrypt
    def encrypt(self, msg, key, iv):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()

        return encryptor.update(msg) + encryptor.finalize()

    # CBC-AES Decrypt
    def decrypt(self, msg, key, iv):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(msg) + decryptor.finalize()