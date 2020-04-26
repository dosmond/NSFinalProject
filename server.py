from socket import *
import pyDH as d
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as bpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


class Server:
    '''
        ip: ip to host at
        port: port to host on
        wmodp: 2^W mod p
        client_id: Client's identifier
    '''
    def __init__(self, ip, port, wmodp, client_id, iv, p):
        self.ip = ip
        self.port = port
        self.wmodp = wmodp
        self.client_id = client_id
        self.iv = iv

        # Only used in the PDM Server
        self.p = p

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        key_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        with open("server_pub.pem", 'w') as f:
            f.write(key_pem.decode())

        self.rsa_private_key = key
        self.rsa_pub_key = key.public_key()
        self.shared_key = None
        self.bmodp = None
        self.client_rsa_pub_key = None

    def run_server(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.ip, self.port))
        sock.listen(1)

        conn, addr = sock.accept()

        return conn, addr

    def set_client_pub_key(self, key):
        self.client_rsa_pub_key = key

    def begin_diffie_hellman(self):
        dh = d.DiffieHellman(group=5)
        public_key = dh.gen_public_key()
        return dh, public_key

    def gen_shared_key(self, dh, client_dh_key):
        return dh.gen_shared_key(client_dh_key)

    def encrypt_using_client_public(self, pub_key, msg):
        return pub_key.encrypt(msg, padding.PKCS1v15())

    def decrypt_using_private_key(self, ciphertext):
        return self.rsa_private_key.decrypt(ciphertext, padding.PKCS1v15())

    def send_dh_pub_key(self, conn, client_rsa_pub_key, dh_pub_key):
        encrypted_key = self.encrypt_using_client_public(client_rsa_pub_key, dh_pub_key)
        conn.sendall(encrypted_key)

    def receive_client_dh_pub_key(self, conn):
        res = conn.recv(4096)
        return self.decrypt_using_private_key(res)

    def set_shared_key(self, key):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)

        self.shared_key = digest.finalize()

    def receive_amodp_and_p(self, conn):
        res = conn.recv(4096)
        msg = self.decrypt(res, self.shared_key, self.iv)
        return msg

    def receive_amodp_norm(self, conn):
        res = conn.recv(4096)
        return int(res.decode())

    def send_bmodp(self, conn, bmodp):
        encrypted_msg = self.encrypt(bmodp, self.shared_key, self.iv)
        conn.sendall(encrypted_msg)

    def send_bmodp_norm(self, conn, bmodp):
        conn.sendall(bmodp)

    # CBC-AES Encrypt
    def encrypt(self, msg, key, iv):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()

        padder = bpad.PKCS7(256).padder()
        msg = padder.update(msg) + padder.finalize()

        return encryptor.update(msg) + encryptor.finalize()

    # CBC-AES Decrypt
    def decrypt(self, msg, key, iv):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        msg = decryptor.update(msg) + decryptor.finalize()
        unpadder = bpad.PKCS7(256).unpadder()

        return unpadder.update(msg) + unpadder.finalize()

    def parse_amod_p_and_p(self, amodp_and_p):
        amodp = int(amodp_and_p[:1].decode())
        p = int(amodp_and_p[1:].decode())

        return amodp, p

    def gen_hash(self, msg):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(msg)
        return digest.finalize()

    def send_first_hash(self, conn, hash):
        encrypted_msg = self.encrypt(hash, self.shared_key, self.iv)
        conn.sendall(encrypted_msg)

    def receive_second_hash(self, conn):
        res = conn.recv(4096)
        msg = self.decrypt(res, self.shared_key, self.iv)
        return msg

    def send_first_hash_norm(self, conn, hash):
        conn.sendall(hash)

    def receive_second_hash_norm(self, conn):
        res = conn.recv(4096)
        return res
