#!/usr/bin/env python3

import socket
import ssl 
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import torch
import transformers

import attest 

star = 30

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server-cert.pem', 'server-key.pem')  # Client cert
context.load_verify_locations('ca.pem')  # CA for server verification
context.check_hostname = False

with open("server-cert.pem", "rb") as f:
    cert_data = f.read()
cert = x509.load_pem_x509_certificate(cert_data)

finger_print = hashlib.sha3_256(
            cert.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).digest()

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 5050))
        s.listen(5)
        
        print(f"\n\033[1m{'*'*star}   [ Step 0 ]   {'*'*star}\033[0m")
        print("[+] Listening for connections...")
    
        with context.wrap_socket(s, server_side=True) as ssock:
            conn, addr = ssock.accept()

            print(f"\n\033[1m{'*'*star}   [ Step 1 ]   {'*'*star}\033[0m")
            print("[+] Connected to client")

            def read_msg():
                length = int.from_bytes(conn.read(len = 4), byteorder="big")
                msg = conn.read(length)
                if len(msg) != length: raise ValueError(f"Bad message {msg}, expected length: {length}, actual: {len(msg)}")
                return msg
    
            def send(msg: bytes):
                conn.send(len(msg).to_bytes(length=4, byteorder="big"))
                conn.send(msg)
    
            nonce = read_msg()
            print(f"\n\033[1m{'*'*star}   [ Step 2 ]   {'*'*star}\033[0m")
            print("[+] Received nonce:", nonce.hex())

            connection_id = finger_print + nonce
            print("[+] My Certificate finger print is", finger_print.hex())
    
    
            # Do attestation
            attestation = attest.generate_attestation_report(connection_id.hex())
            attestation = attestation.encode(encoding="utf-8")
            print(f"\n\033[1m{'*'*star}   [ Step 3 ]   {'*'*star}\033[0m")
            print("[+] Generated TEE attestation:", len(attestation), "bytes")
            send(attestation)
   
            while True:
                prompt_bytes = read_msg()
                if prompt_bytes == b"\xde\xad":
                    break

                prompt_text = prompt_bytes.decode(encoding="utf-8")

                print(f"\n\033[1m{'*'*star}   [ Step 4 ]   {'*'*star}\033[0m")
                print("[+] Receaved user prompt:\033[3;32m", prompt_text, "\033[0m")
                print("[*] Waiting for model answer...")

    
                # Do inference 
                pipe = transformers.pipeline("text-generation", model="TinyLlama/TinyLlama-1.1B-Chat-v1.0", torch_dtype=torch.bfloat16)
                messages = [
                    {
                        "role": "system",
                        "content": "You are a helpful assistant. Always be polite. Always be enthusiastic",
                    },
                    {
                        "role": "user", 
                        "content": prompt_text
                    },
                ]
                prompt = pipe.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                outputs = pipe(prompt, max_new_tokens=256, do_sample=True, temperature=0.8, top_k=50, top_p=0.95)
                full_output = outputs[0]["generated_text"]
                response_only: str = full_output[len(prompt):].strip()

                answer = response_only
                print(f"\n\033[1m{'*'*star}   [ Step 5 ]   {'*'*star}\033[0m")
                print("[+] Sent answer:\033[3;32m", answer, "\033[0m")
                send(answer.encode(encoding="utf-8"))

                prompt_hash = hashlib.sha3_256(prompt_bytes).digest()
                print(f"\n\033[1m{'*'*star}   [ Step 5 ]   {'*'*star}\033[0m")
                print("[+] Sent promt hash:", prompt_hash.hex())
                send(prompt_hash)

            print("\n\n[+] Exit.")

except Exception as e:
    print(f"Caught error: {e}")
    print("The client has likely reset the connection")
