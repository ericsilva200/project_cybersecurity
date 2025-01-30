import os
import base64
#pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

encrypted_folder = f"{os.getcwd()}/encrypted_files"
decrypted_folder = f"{os.getcwd()}/decrypted_files"

#Gera uma chave aleatória de 32 Bytes para a Criptografia
def generate_key():
    key = get_random_bytes(32)  # AES-256
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

#Realiza a leitura da chave
def load_key():
    return open("secret.key", "rb").read()

#Função para criptografar o arquivo
def encrypt_file(file_name):
    file_path = f"{os.getcwd()}/files/{file_name}"

    if not os.path.exists(file_path):
        return print("O Arquivo não existe no diretório")
    
    print("Iniciando a criptografia...")
    key = load_key()
    cipher = AES.new(key, AES.MODE_GCM)
    
    with open(file_path, "rb") as file:
        plaintext = file.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    encrypted_file_path = os.path.join(encrypted_folder, os.path.basename(file_path) + ".enc")
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(cipher.nonce + tag + ciphertext)
    
    print(f"Arquivo criptografado salvo em: {encrypted_file_path}")
    decrypt_file(encrypted_file_path)

#Funçao de Descriptografia
def decrypt_file(encrypted_file_path):
    print("Iniciando a descriptografia...")
    key = load_key()
    
    with open(encrypted_file_path, "rb") as encrypted_file:
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        ciphertext = encrypted_file.read()
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    decrypted_file_path = os.path.join(decrypted_folder, os.path.basename(encrypted_file_path).replace(".enc", ""))
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
    
    print(f"Arquivo descriptografado salvo em: {decrypted_file_path}")

# Criar chave se não existir
if not os.path.exists("secret.key"):
    generate_key()
