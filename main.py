from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import argparse
import os


def encrypt_file(file_name, key):
    # Import public key, create session key and open file
    recipient_key = RSA.import_key(open(key).read())
    session_key = get_random_bytes(16)
    with open(file_name, "rb") as f:
        data = f.read()

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Write encrypted file to disk
    new_file_name = os.path.basename(file_name)
    with open("encrypted_" + new_file_name + ".bin", "wb") as f:
        f.write(enc_session_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)


def decrypt_file(file_name, key):
    # Import Private key and open file
    private_key = RSA.import_key(open(key).read())
    with open(file_name, "rb") as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    de_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Fix name and write decrypted file to disk
    new_file_name = file_name.replace("encrypted_", "decrypted_", 1)
    with open(os.path.basename(new_file_name)[:-4], "wb") as f:
        f.write(de_data)


def main():
    parser = argparse.ArgumentParser(description="File Encryption/Decryption Tool")

    # Creates two separate groups where only one can be used at a time (-encrypt/-decrypt)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-encrypt", action="store_true", help="Encrypt a file")
    group.add_argument("-decrypt", action="store_true", help="Decrypt a file")

    # lays out the format of the arguments
    parser.add_argument("-f", "--file", required=True, help="File to encrypt")
    parser.add_argument("-pk", "--public_key", help="Public key for encryption")
    parser.add_argument("-sk", "--private_key", help="Private Key for decryption")

    args = parser.parse_args()

    # Calls appropriate functions
    if args.encrypt:
        if not args.public_key:
            print("Error: Public key (-pk) is required for encryption")
            return
        encrypt_file(args.file, args.public_key)
    elif args.decrypt:
        if not args.private_key:
            print("Error: Private key (-pk) is required for decryption")
            return
        decrypt_file(args.file, args.private_key)


if __name__ == "__main__":
    main()
