import socket
import json
import time
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

SERVER_HOST = 'localhost'
SERVER_PORT = 6969
BUFFER_SIZE = 4096


KEY_FILE = 'client_key.pem'


username = ""
private_key = None
token = None


def load_or_generate_keys():
    global private_key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            private_key = RSA.import_key(f.read())
    else:
        private_key = RSA.generate(2048)
        with open(KEY_FILE, 'wb') as f:
            f.write(private_key.export_key())


def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    return sock


def send_json(sock, data):
    sock.send(json.dumps(data).encode('utf-8'))


def receive(sock):
    return sock.recv(BUFFER_SIZE)


def register(sock, name):
    pub_key = private_key.publickey().export_key().decode('utf-8')
    payload = {
        'name': name,
        'pub': pub_key
    }
    send_json(sock, {'command': 'register', 'payload': payload})
    print(sock.recv(BUFFER_SIZE).decode('utf-8'))


def login(sock, name):
    global token
    payload = {'name': name}
    send_json(sock, {'command': 'login', 'payload': payload})


    encrypted_token = sock.recv(BUFFER_SIZE)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_token = cipher_rsa.decrypt(encrypted_token).decode('utf-8')
    token = decrypted_token

    payload = {
        'name': name,
        'token-sig': decrypted_token
    }
    send_json(sock, {'command': 'login-verif', 'payload': payload})
    print(sock.recv(BUFFER_SIZE).decode('utf-8'))


def send_message(sock, sender, receiver, message):

    payload = {
        'sender': sender,
        'receiver': receiver,
        'key_known': False
    }
    send_json(sock, {
        'command': 'send',
        'sender_timestamp': str(time.time()),
        'payload': payload
    })

    response = sock.recv(BUFFER_SIZE).decode('utf-8')
    if "BEGIN PUBLIC KEY" not in response:
        print(response)
        return

    receiver_pub_key = RSA.import_key(response.encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)


    aes = get_random_bytes(16)
    encrypted_msg = message[::-1]

    payload = {
        'sender': sender,
        'receiver': receiver,
        'aes': aes.hex(),
        'msg': encrypted_msg,
        'key_known': True
    }

    send_json(sock, {
        'command': 'send',
        'sender_timestamp': str(time.time()),
        'payload': payload
    })
    print("Wiadomość wysłana")


def sync(sock, name, from_ts, to_ts):
    payload = {
        'name': name,
        'from': from_ts,
        'to': to_ts
    }
    send_json(sock, {'command': 'sync', 'payload': payload})
    try:
        while True:
            msg = sock.recv(BUFFER_SIZE).decode('utf-8')
            if not msg:
                break
            print("[SYNCHRONIZACJA]", msg)
    except Exception:
        pass


def listener(sock):
    while True:
        try:
            msg = sock.recv(BUFFER_SIZE).decode('utf-8')
            if msg:
                print(f"[WIADOMOŚĆ ODEBRANA]: {msg}")
        except Exception:
            break


def main():
    global username
    load_or_generate_keys()
    sock = connect_to_server()

    print("1. Rejestracja")
    print("2. Logowanie")
    option = input("Wybierz: ")

    username = input("Podaj nazwę użytkownika: ")

    if option == '1':
        register(sock, username)
    elif option == '2':
        login(sock, username)

    threading.Thread(target=listener, args=(sock,), daemon=True).start()

    while True:
        print("\n--- MENU ---")
        print("1. Wyślij wiadomość")
        print("2. Synchronizuj wiadomości")
        print("3. Wyloguj")
        print("4. Zakończ")
        choice = input("Wybierz: ")

        if choice == '1':
            to_user = input("Do kogo wysłać: ")
            msg = input("Treść wiadomości: ")
            send_message(sock, username, to_user, msg)
        elif choice == '2':
            f = input("Od (timestamp): ")
            t = input("Do (timestamp): ")
            # Uruchomienie synchronizacji w osobnym wątku
            threading.Thread(target=sync, args=(sock, username, f, t), daemon=True).start()
        elif choice == '3':
            send_json(sock, {'command': 'logout', 'payload': {'name': username}})
            print(sock.recv(BUFFER_SIZE).decode('utf-8'))
        elif choice == '4':
            send_json(sock, {'command': 'quit'})
            break


if __name__ == '__main__':
    main()
