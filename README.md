# 🔐 File-Encrypter

A Python desktop application for secure file encryption and decryption using AES-256, RSA-2048/4096, and hybrid encryption methods.

## Features

- **Multiple Encryption Methods**
  - AES-256 symmetric encryption with password-based key derivation
  - RSA-2048/4096 asymmetric encryption with public/private key pairs
  - Hybrid encryption (RSA to encrypt AES key, AES for file content)

- **User-Friendly Interface**
  - Intuitive Tkinter GUI with drag & drop file support
  - Real-time progress bar and status updates
  - Encryption mode selection via dropdown
  - Clear error messages and validation

- **Advanced Security**
  - Random IV generation for AES encryption
  - Secure PBKDF2 key derivation with random salt
  - PKCS#7 padding for AES
  - Secure file handling with optional original file shredding

- **Key Management**
  - Generate and export/import RSA key pairs
  - Password-based key derivation for AES
  - Secure storage of encryption metadata

## Installation

```bash
# Clone the repository
git clone https://github.com/Krishna-2307/File-Encrypter.git
cd File-Encrypter

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install cryptography
```

## Usage

### Starting the Application

```bash
python main.py
```

### Encrypting a File

1. Launch the application
2. Click "Browse" or drag a file into the drop area
3. Select "Encrypt" operation
4. Choose encryption method (AES, RSA, or Hybrid)
5. For AES: Enter a strong password
   For RSA: Select or generate a public key
   For Hybrid: Both password and public key
6. Click "Encrypt" button
7. Choose where to save the encrypted file

### Decrypting a File

1. Launch the application
2. Select the encrypted file
3. Choose "Decrypt" operation
4. For AES: Enter the same password used for encryption
   For RSA: Select the private key corresponding to the public key used for encryption
   For Hybrid: Both password and private key
5. Click "Decrypt" button
6. Choose where to save the decrypted file



## Security Considerations

- **Password Strength**: Use strong, unique passwords for AES encryption
- **Key Management**: Store private keys securely and never share them
- **File Deletion**: Consider enabling secure deletion of original files after encryption
- **Memory Security**: All sensitive data is cleared from memory after use

## Dependencies

- Python 3.6+
- cryptography library

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
