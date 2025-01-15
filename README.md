# **Firewall and Public-Key Encryption System**

## **Project Overview**
This repository contains two main components:

1. **Public-Key Encryption System**: Implements an alternative public-key encryption method, supporting key generation, encryption, and decryption. It follows a super-increasing sequence-based approach for key generation.
2. **Firewall System**: Implements a rule-based firewall that allows adding, listing, and removing IP-based access control rules. It supports single IPs, ranges, and bidirectional rules.

---

## **Table of Contents**
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Public-Key Encryption](#public-key-encryption)
  - [Firewall System](#firewall-system)
- [Example](#example)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## **Features**

### **Public-Key Encryption System**
- Supports key generation with lengths ranging from 2 to 64.
- Encrypts plaintext by converting it to binary and splitting into chunks.
- Decrypts ciphertext using private keys and reconstructs the original text.
- Handles modular arithmetic and prime number operations.

### **Firewall System**
- Supports rule addition for single IPs, ranges, and bidirectional rules.
- Allows listing of rules based on filters (rule number, direction, IP address).
- Can save and load rules to/from files.
- Handles duplicate rules and ensures priority adjustments.

---

## **Installation**
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>

 2.	Install Python 3 and necessary packages:
    ```bash
    pip install -r requirements.txt


Usage

1. Public-Key Encryption

To run the encryption program:
```bash
python Task1-Encryption.py
```

Available options:
	•	generate: Generate public and private keys.
	•	encrypt: Encrypt a text file using the public key.
	•	decrypt: Decrypt a file using the private key.

Example Commands:
```bash
Choose action (generate/encrypt/decrypt): generate
Choose e(n) (between 2 and 64): 5
```

2. Firewall System

To run the firewall program:
```bash
python firewall2.py
```

Available commands:
	•	add: Add a rule (e.g., add 1 -in 192.168.1.10).
	•	remove: Remove a rule (e.g., remove 1 -in).
	•	list: List all rules or filter by direction, address, etc.
	•	save: Save rules to a file.
	•	load: Load rules from a file.

Example

Public-Key Encryption Example

Plaintext:
Planning is key to achieving goals.

Key Length: 5
Encrypted Ciphertext: [60, 313, 500, ...]

Decrypted Output:
Planning is key to achieving goals.

Firewall Example

```bash
Enter command: add 1 -in 192.168.1.15
Enter command: list
Rule 1 | Direction: -in | Address: 192.168.1.15
Enter command: save
Enter filename to save rules to: rules.txt
```


Contributing

Contributions are welcome! Please follow these steps:
	1.	Fork the repository.
	2.	Create a new branch: git checkout -b feature-name.
	3.	Commit changes: git commit -m "Add feature".
	4.	Push to your branch: git push origin feature-name.
	5.	Create a pull request.
