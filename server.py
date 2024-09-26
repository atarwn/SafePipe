import os
import socket
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 65432
RATE_LIMIT = 0.1
last_request_time = {}

def load_html_page(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return None

def derive_key(shared_key):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

def encrypt_message(key, plaintext):
    try:
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    except Exception:
        return None

def check_rate_limit(ip):
    global last_request_time
    now = time.time()
    if ip in last_request_time and now - last_request_time[ip] < RATE_LIMIT:
        return False
    last_request_time[ip] = now
    return True

def start_server():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print(f'Сервер запущен на {HOST}:{PORT}')
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    print(f'Подключен клиент {addr}')

                    server_pub_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    conn.sendall(server_pub_key_bytes)

                    try:
                        client_pub_key_bytes = conn.recv(1024)
                        client_public_key = serialization.load_pem_public_key(client_pub_key_bytes, backend=default_backend())

                        shared_key = private_key.exchange(ec.ECDH(), client_public_key)
                        symmetric_key = derive_key(shared_key)
                    except Exception:
                        conn.sendall(b"600")
                        continue

                    data = conn.recv(1024).decode()
                    if data.startswith('GET '):
                        file_path = data.split(' ')[1].strip('/')
                        if not file_path:
                            file_path = 'index'

                        full_path = os.path.join('./public', file_path)

                        if check_rate_limit(addr[0]):
                            html_content = load_html_page(full_path)
                            if html_content:
                                encrypted_content = encrypt_message(symmetric_key, html_content)
                                if encrypted_content:
                                    conn.sendall(b"200" + encrypted_content)
                                else:
                                    conn.sendall(b"500")
                            else:
                                conn.sendall(b"404")
                        else:
                            conn.sendall(b"429")
                    else:
                        conn.sendall(b"400")
            except:
                conn.sendall(b"500")

if __name__ == '__main__':
    start_server()