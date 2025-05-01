from fastapi import FastAPI, UploadFile, File, HTTPException
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.middleware.cors import CORSMiddleware
import secrets
import hashlib
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/encrypt")
async def encrypt_file(file: UploadFile = File(...)):
    plaintext = await file.read()
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return {
        "encrypted_data": (iv + ciphertext).hex(),
        "key": key.hex()
    }

@app.post("/decrypt")
async def decrypt_file(file: UploadFile = File(...), key_hex: str = ""):
    data = await file.read()
    key = bytes.fromhex(key_hex)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return {"decrypted_data": plaintext.decode('utf-8')}