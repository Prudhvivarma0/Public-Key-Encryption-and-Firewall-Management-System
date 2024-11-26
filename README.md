# Public-Key Encryption and Firewall Management System

## Table of Contents

- [Overview](#overview)
- [Project Features](#project-features)
  - [Public-Key Encryption System](#public-key-encryption-system)
  - [Firewall Rule Management](#firewall-rule-management)
- [Installation](#installation)
- [Usage](#usage)
  - [Task 1: Public-Key Encryption](#task-1-public-key-encryption)
  - [Task 2: Firewall Management](#task-2-firewall-management)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This project implements two key functionalities:

1. A custom public-key encryption system based on a novel method of key generation and encryption.
2. A firewall rule management application to control access to a network based on IPv4 packet filtering rules.

The goal is to demonstrate practical applications of cryptographic methods and firewall systems using Python.

---

## Project Features

### Public-Key Encryption System

- **Key Generation:** Generate public and private keys based on custom rules.
- **Encryption:** Encrypt plaintext messages into ciphertext using the public key.
- **Decryption:** Decrypt ciphertext into plaintext using the private key.
- **Security Assumptions:** The encryption relies on modular arithmetic and the mathematical properties of keys.

### Firewall Rule Management

- **Add Rules:** Dynamically add IPv4-based rules for incoming and outgoing packets.
- **Remove Rules:** Delete specific rules or specific traffic directions.
- **List Rules:** Display all rules with filtering options based on IP address, range, or direction.
- **Command-Line Interface:** Simple command-line commands for managing rules.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/encryption-firewall-management.git
   ```

## Navigate to the Project Directory

```bash
cd encryption-firewall-management
```

## Install the Necessary Python Dependencies
```bash
pip install -r requirements.txt
```

## Contributing
Contributions are welcome! Please fork this repository and submit a pull request with any enhancements, bug fixes, or additional features.
