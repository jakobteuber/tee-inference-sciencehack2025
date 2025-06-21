import ssl
import hashlib
import socket
from sys import exit
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import attest

HOST = "127.0.0.1"
PORT = 5050

def pretty_print(step_nr):
    decoration = '*' *30
    print(f"\n{decoration}   [ Step {step_nr} ]   {decoration}")

def open_tls_socket():
    context = ssl.create_default_context()
 
    ## certificate workaround
    context.load_verify_locations("ca.pem")

    s = socket.create_connection((HOST,PORT))
    tls_sock = context.wrap_socket(s, server_hostname=HOST)

    print("[+] TLS socket is live and usable")
    return tls_sock

## ------------  Send and receive helper functions with encoding ------------
def send(msg : bytes):
    msg_len = len(msg).to_bytes(4, 'big')
    tls_sock.send(msg_len)
    tls_sock.send(msg)

def receive() -> bytes:
    msg_len = tls_sock.recv(4)
    msg_len = int.from_bytes(msg_len, 'big')
    return tls_sock.recv(msg_len)

# verifies intel attestation from tee and correct binding to the current key
def verify_attestation(attestation, public_key, nonce) -> bool:
    valid, data = attest.verify_attestation_report(attestation)
    pk_digest = hashlib.sha3_256(public_key).hexdigest()
    old_data = pk_digest + nonce
    
    print(f"[+] {pk_digest=}\n[+] {nonce=}")
    return valid and old_data == data

def extract_public_key():
    server_cert = x509.load_der_x509_certificate(tls_sock.getpeercert(binary_form=True))
    public_key = server_cert.public_key()

    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

def get_user_prompt() -> bytes:
    user_input = input()

    if user_input == "":
        user_input = "What time is it?"

    print(f"[+] Sending prompt\n\nUSER PROMPT: \033[3;32m{user_input}\033[0m")
    return user_input.encode()

def verify_prompt(prompt, hash_digest) -> bool:
    prompt_hash = hashlib.sha3_256(prompt).digest()
    return prompt_hash == hash_digest

# Open socket with a TLS connection to the TEE
pretty_print(1)
tls_sock = open_tls_socket()
TEE_public_key = extract_public_key()
print(f"[+] Server public key: {TEE_public_key}")

# Generate chalenge for the server
pretty_print(2)
nonce = os.urandom(32)
send(nonce)
print("[+] Sending challenge to the server.")
print(f"[+] Nonce {nonce.hex()}")

pretty_print(3)
attestation = receive()

print("[+] Verfying TEE attestation...")
if not verify_attestation(attestation.decode(), TEE_public_key, nonce.hex()):
    print("[-] Attestation failed")
    exit()

else:
    print("[+] Attestation succesful")

while True:
    pretty_print(4)
    print("[+] Type in your question (\033[1mENTER\033[0m for default prompt or \033[1mCtrl+C\033[0m to exit)")
    try:
        prompt = get_user_prompt()
    except KeyboardInterrupt:
        print("[+] Exiting...")
        send(bytes.fromhex("dead"))
        break
    send(prompt)

    pretty_print(5)
    print("[+] Wating for server response...")
    prompt_response = receive()
    prompt_digest = receive()
    print("[+] Received answer")

    pretty_print(6)
    if not verify_prompt(prompt, prompt_digest):
        print("[-] Prompt verification failed")
        exit()

    else:
        print("[+] Prompt verification succesful")


    print(f"\nRESPONSE: \033[3;32m{prompt_response.decode()}\033[0m")
