# AES-OFB Implementation for Trusted Computing Assignment

## Overview
This repository hosts the implementation of the Advanced Encryption Standard (AES) in Output Feedback (OFB) mode, developed as part of a Trusted Computing and Security Models assignment (Roll No. 23). The project includes Python scripts for encrypting and decrypting data, measuring performance on a 1MB file, and supporting materials for a security analysis report. The code adheres to the assignment requirements, utilizing the `pycryptodome` library for AES operations.

## Files
- `aes_ofb.py`: Script for Task 1, implementing AES-OFB encryption and decryption with plaintext input and key support (hex or base64).
- `aes_ofb_performance.py`: Script for Task 3, measuring encryption/decryption times and ciphertext size for a 1MB file.
- `test_1mb.txt`: A 1MB text file used for performance testing.

## Prerequisites
- Python 3.6 or higher.
- Install required library:
  ```bash
  pip install pycryptodome
  ```
- Git installed for version control (optional but recommended).

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/harshues04/AES-OFB-Mode-of-operation.git
   cd AES_OFB_Assignment
   ```
2. Install the dependency:
   ```bash
   pip install pycryptodome
   ```
3. Ensure `test_1mb.txt` exists (generate if needed):
   ```python
   with open('test_1mb.txt', 'w') as f:
       f.write('A' * 1024 * 1024)
   ```

## Usage
### Task 1: AES-OFB Implementation
- Run the encryption/decryption script:
  ```bash
  python aes_ofb.py
  ```
- Enter plaintext (e.g., "Hello, this is a test message!") and a 128-bit key (e.g., hex: `000102030405060708090a0b0c0d0e0f` or base64: `AAECAwQFBgcICQoLDA0ODw==`).
- Output includes plaintext, key (hex), IV (hex), ciphertext (base64), decrypted text, and verification status.

### Task 3: Performance Measurement
- Run the performance script:
  ```bash
  python aes_ofb_performance.py
  ```
- Enter the same 128-bit key used in Task 1.
- Output includes encryption time, decryption time, ciphertext size, and verification status for the 1MB file.


## Performance Results (Example)
| Metric            | Value          |
|-------------------|----------------|
| Encryption Time   | 0.081-0.891 s  |
| Decryption Time   | 0.044-0.845 s  |
| Ciphertext Size   | 1048592 bytes  |

## Notes
- The ciphertext size includes a 16-byte IV prepended to the encrypted data.
- Avoid reusing the same IV with the same key to prevent security vulnerabilities.
- Test on your local machine to capture exact performance metrics for the report.
