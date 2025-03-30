# CipherSafe

A command-line tool to encrypt and decrypt files using asymmetric and symmetric encryption (RSA & AES). This tool securely encrypts files and ensures that sensitive data remains protected.

---
### Table of Contents
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Possible Improvements](#possible-improvements)

---

### Description
This is a simple Python-based file encryption tool that allows you to securely encrypt and decrypt files using RSA and AES algorithms. 
The tool supports both encryption and decryption of files, with support for handling public and private keys. It can be used 
to protect sensitive files, ensuring that unauthorized users cannot access them.
This tool uses a **Hybrid Encryption** approach, combining the strengths of **RSA** (asymmetric encryption) and **AES** (symmetric encryption).

1. **AES Encryption**:  
   AES is used to encrypt the actual file data because it is fast and efficient for large files. A unique **session key** is generated for AES encryption, which is a random key used only for this particular file.

2. **RSA Encryption**:  
   RSA is used to securely encrypt the AES session key. The session key is then encrypted with the recipient’s **public RSA key**, ensuring that only the recipient (who possesses the private key) can decrypt the session key.

3. **Final Encrypted File**:  
   The encrypted file contains:
   - The **AES-encrypted data** (actual content of the file).
   - The **RSA-encrypted AES session key** (for secure key sharing).
   - A **tag** for verifying data integrity.

This combination ensures that file encryption is both **secure** (via RSA for key exchange) and **efficient** (via AES for file data encryption).

---

### **Installation** 
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/your-repository-name.git
   cd your-repository-name

2. Install required dependencies:
   ```bash
   pip install pycryptodome
   
---

### **Usage**
how to run the program from the command line.

#### Encryption:
```bash
python main.py -encrypt -f <file_to_encrypt> -pk <public_key.pem>
```

#### Decryption:
```bash
python main.py -decrypt -f <file_to_decrypt> -sk <private_key.pem>
```

### Options:
- `-h, --help`: Show help message.
- `-encrypt`: Encrypt a file.
- `-decrypt`: Decrypt a file.
- `-f FILE, --file FILE`: Specify the file to encrypt or decrypt (required).
- `-pk PUBLIC_KEY, --public_key PUBLIC_KEY`: Public key for encryption (required for encryption).
- `-sk PRIVATE_KEY, --private_key PRIVATE_KEY`: Private key for decryption (required for decryption).

### Exapmles:
(NOTE): The order of the options does not matter 
```bash
python main.py -f secret_document.txt -pk public.pem -encrypt 
python main.py -sk private.pem  -f encrypted_secret_document.txt.bin -decrypt
```
---

### **Features**
- Encrypts files using AES (Symmetric encryption) and RSA (Asymmetric encryption).
- Decrypts files with AES and RSA.
- Supports both encryption and decryption with customizable file and key options.
- Handles .bin extension for encrypted files and allows you to strip it upon decryption.
- Command-line interface with argparse for easy user interaction.

---


### **Possible Improvements**
- Better Error Handling: Improve error handling for edge cases, such as corrupted files or incorrect keys.
- File Integrity Checking: Implement checks to ensure the integrity of the encrypted/decrypted files (e.g using checksums).
- Password Protection: Add an option for the user to password-protect encrypted files with a passphrase.
- Implement a feature to automatically generate RSA public and private key pairs if the user doesn't have a key pair.
