import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import secrets
import json

class CryptoUtils:
    @staticmethod
    def generate_rsa_key_pair(key_size=2048):
        """Generate an RSA key pair of the specified size"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def save_rsa_keys(private_key, public_key, private_path, public_path):
        """Save RSA keys to the specified paths"""
        # Serialize private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write keys to files
        with open(private_path, 'wb') as f:
            f.write(pem_private)
        
        with open(public_path, 'wb') as f:
            f.write(pem_public)
    
    @staticmethod
    def load_rsa_key(path, is_private=True):
        """Load an RSA key from a file"""
        with open(path, 'rb') as key_file:
            if is_private:
                key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            else:
                key = serialization.load_pem_public_key(
                    key_file.read()
                )
        return key
    
    @staticmethod
    def aes_encrypt_file(file_path, key, output_path, update_progress=None):
        """Encrypt a file using AES-CBC"""
        # Ensure key is proper length (16, 24, or 32 bytes)
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes long")
        
        # Generate a random 16-byte IV
        iv = secrets.token_bytes(16)
        
        # Create AES cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            # Write IV to output file
            out_file.write(iv)
            
            # Create padder
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            
            # Process file in chunks
            chunk_size = 64 * 1024  # 64KB chunks
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break
                
                bytes_processed += len(chunk)
                if update_progress:
                    progress = bytes_processed / file_size * 100
                    update_progress(progress)
                
                # Pad the last chunk
                if len(chunk) < chunk_size:
                    padded_chunk = padder.update(chunk) + padder.finalize()
                    encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                else:
                    encrypted_chunk = encryptor.update(chunk)
                
                out_file.write(encrypted_chunk)
    
    @staticmethod
    def aes_decrypt_file(file_path, key, output_path, update_progress=None):
        """Decrypt a file using AES-CBC"""
        # Ensure key is proper length
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes long")
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            # Read IV from the beginning of the file
            iv = in_file.read(16)
            bytes_processed += 16
            
            # Create AES cipher
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Create unpadder
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            
            # Process file in chunks
            chunk_size = 64 * 1024  # 64KB chunks
            encrypted_data = b''
            
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break
                
                bytes_processed += len(chunk)
                if update_progress:
                    progress = bytes_processed / file_size * 100
                    update_progress(progress)
                
                encrypted_data += chunk
            
            # Decrypt the data
            decrypted_data = decryptor.update(encrypted_data)
            try:
                decrypted_data += decryptor.finalize()
                unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
                out_file.write(unpadded_data)
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}. Possible incorrect key or corrupted file.")
    
    @staticmethod
    def rsa_encrypt_file(file_path, public_key_path, output_path, update_progress=None):
        """Encrypt a file using RSA"""
        # Load the public key
        public_key = CryptoUtils.load_rsa_key(public_key_path, is_private=False)
        
        # Determine max chunk size (RSA key size in bytes - padding overhead)
        key_size_bytes = public_key.key_size // 8
        chunk_size = key_size_bytes - 42  # OAEP padding with SHA-256 requires 42 bytes
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            # Process file in chunks
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break
                
                bytes_processed += len(chunk)
                if update_progress:
                    progress = bytes_processed / file_size * 100
                    update_progress(progress)
                
                # Encrypt chunk
                encrypted_chunk = public_key.encrypt(
                    chunk,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Write the length of the encrypted chunk (4 bytes) followed by the chunk
                chunk_len = len(encrypted_chunk).to_bytes(4, byteorder='big')
                out_file.write(chunk_len)
                out_file.write(encrypted_chunk)
    
    @staticmethod
    def rsa_decrypt_file(file_path, private_key_path, output_path, update_progress=None):
        """Decrypt a file using RSA"""
        # Load the private key
        private_key = CryptoUtils.load_rsa_key(private_key_path, is_private=True)
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            while True:
                # Read the length of the encrypted chunk
                chunk_len_bytes = in_file.read(4)
                if not chunk_len_bytes or len(chunk_len_bytes) < 4:
                    break
                
                chunk_len = int.from_bytes(chunk_len_bytes, byteorder='big')
                
                # Read the encrypted chunk
                encrypted_chunk = in_file.read(chunk_len)
                if not encrypted_chunk or len(encrypted_chunk) < chunk_len:
                    break
                
                bytes_processed += len(encrypted_chunk) + 4
                if update_progress:
                    progress = bytes_processed / file_size * 100
                    update_progress(progress)
                
                # Decrypt chunk
                try:
                    decrypted_chunk = private_key.decrypt(
                        encrypted_chunk,
                        rsa_padding.OAEP(
                            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    out_file.write(decrypted_chunk)
                except Exception as e:
                    raise ValueError(f"Decryption failed: {str(e)}. Possible incorrect key or corrupted file.")
    
    @staticmethod
    def hybrid_encrypt_file(file_path, public_key_path, output_path, update_progress=None):
        """Encrypt a file using AES with the key encrypted by RSA"""
        # Generate a random AES key
        aes_key = secrets.token_bytes(32)  # 256-bit AES key
        
        # Load the public key
        public_key = CryptoUtils.load_rsa_key(public_key_path, is_private=False)
        
        # Encrypt the AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Generate a random IV for AES
        iv = secrets.token_bytes(16)
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            # Write metadata
            key_len = len(encrypted_aes_key)
            metadata = {
                'key_len': key_len,
                'mode': 'hybrid'
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            metadata_len = len(metadata_json).to_bytes(4, byteorder='big')
            
            out_file.write(metadata_len)
            out_file.write(metadata_json)
            out_file.write(encrypted_aes_key)
            out_file.write(iv)
            
            # Create AES cipher
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Create padder
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            
            # Process file in chunks
            chunk_size = 64 * 1024  # 64KB chunks
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break
                
                bytes_processed += len(chunk)
                if update_progress:
                    progress = bytes_processed / file_size * 100
                    update_progress(progress)
                
                # Pad the last chunk
                if len(chunk) < chunk_size:
                    padded_chunk = padder.update(chunk) + padder.finalize()
                    encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                else:
                    encrypted_chunk = encryptor.update(chunk)
                
                out_file.write(encrypted_chunk)
    
    @staticmethod
    def hybrid_decrypt_file(file_path, private_key_path, output_path, update_progress=None):
        """Decrypt a file using AES with the key decrypted by RSA"""
        # Load the private key
        private_key = CryptoUtils.load_rsa_key(private_key_path, is_private=True)
        
        file_size = os.path.getsize(file_path)
        bytes_processed = 0
        
        with open(file_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            # Read metadata
            metadata_len_bytes = in_file.read(4)
            metadata_len = int.from_bytes(metadata_len_bytes, byteorder='big')
            metadata_json = in_file.read(metadata_len)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            if metadata.get('mode') != 'hybrid':
                raise ValueError("Not a hybrid encrypted file")
            
            key_len = metadata.get('key_len')
            encrypted_aes_key = in_file.read(key_len)
            
            # Decrypt the AES key
            try:
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                raise ValueError(f"Failed to decrypt AES key: {str(e)}. Incorrect RSA key.")
            
            # Read IV
            iv = in_file.read(16)
            
            # Create AES cipher
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Create unpadder
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            
            # Calculate header size
            header_size = 4 + metadata_len + key_len + 16
            bytes_processed += header_size
            
            # Read encrypted data
            encrypted_data = in_file.read()
            bytes_processed += len(encrypted_data)
            if update_progress:
                update_progress(100)  # File reading complete
            
            # Decrypt the data
            try:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
                out_file.write(unpadded_data)
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}. Possible corrupted file.")


class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryptor & Decryptor")
        self.root.geometry("700x500")
        self.root.configure(padx=20, pady=20)
        
        self.selected_file = None
        self.encryption_type = tk.StringVar(value="AES")
        self.operation_mode = tk.StringVar(value="encrypt")
        self.key_file_path = None
        
        self.create_widgets()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Operation mode selection (Encrypt/Decrypt)
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode")
        mode_frame.pack(fill=tk.X, pady=10)
        
        encrypt_radio = ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.operation_mode, value="encrypt", command=self.update_ui)
        encrypt_radio.pack(side=tk.LEFT, padx=20, pady=5)
        
        decrypt_radio = ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.operation_mode, value="decrypt", command=self.update_ui)
        decrypt_radio.pack(side=tk.LEFT, padx=20, pady=5)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection")
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Encryption type frame
        encryption_frame = ttk.LabelFrame(main_frame, text="Encryption Method")
        encryption_frame.pack(fill=tk.X, pady=10)
        
        encryption_types = ["AES", "RSA", "Hybrid"]
        encryption_dropdown = ttk.Combobox(encryption_frame, textvariable=self.encryption_type, values=encryption_types, state="readonly")
        encryption_dropdown.pack(side=tk.LEFT, padx=10, pady=5)
        encryption_dropdown.bind("<<ComboboxSelected>>", self.update_key_section)
        
        # Key section frame (will be updated based on encryption type)
        self.key_frame = ttk.LabelFrame(main_frame, text="Key Settings")
        self.key_frame.pack(fill=tk.X, pady=10)
        
        # Create initial key section (for AES)
        self.create_aes_key_section()
        
        # Generate RSA Keys button
        self.gen_keys_button = ttk.Button(main_frame, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.gen_keys_button.pack(pady=10)
        
        # Process button (Encrypt/Decrypt)
        self.process_button_frame = ttk.Frame(main_frame)
        self.process_button_frame.pack(fill=tk.X, pady=10)
        
        self.process_button = ttk.Button(self.process_button_frame, text="Encrypt File", command=self.process_file)
        self.process_button.pack(pady=5)
        
        # Progress frame
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack(pady=5)
        
        # Update UI based on initial encryption type
        self.update_key_section()
    
    def create_aes_key_section(self):
        # Clear existing widgets
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        
        # Add AES key entry
        key_label = ttk.Label(self.key_frame, text="AES Key (16, 24, or 32 characters):")
        key_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.key_entry = ttk.Entry(self.key_frame, width=50)
        self.key_entry.pack(fill=tk.X, padx=10, pady=5)
    
    def create_rsa_key_section(self):
        # Clear existing widgets
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        
        # Add RSA key file selection
        operation = "encryption" if self.operation_mode.get() == "encrypt" else "decryption"
        key_type = "Public" if self.operation_mode.get() == "encrypt" else "Private"
        
        key_label = ttk.Label(self.key_frame, text=f"RSA {key_type} Key for {operation}:")
        key_label.pack(anchor=tk.W, padx=10, pady=5)
        
        key_frame = ttk.Frame(self.key_frame)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.key_file_label = ttk.Label(key_frame, text="No key file selected")
        self.key_file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_key_button = ttk.Button(key_frame, text="Browse", command=self.browse_key_file)
        browse_key_button.pack(side=tk.RIGHT)
    
    def create_hybrid_key_section(self):
        # Hybrid uses RSA keys, so reuse the RSA key section
        self.create_rsa_key_section()
    
    def update_key_section(self, event=None):
        encryption_type = self.encryption_type.get()
        
        if encryption_type == "AES":
            self.create_aes_key_section()
        elif encryption_type == "RSA":
            self.create_rsa_key_section()
        elif encryption_type == "Hybrid":
            self.create_hybrid_key_section()
    
    def update_ui(self):
        # Update button text based on operation mode
        operation = self.operation_mode.get().capitalize()
        self.process_button.config(text=f"{operation} File")
        
        # Update key section based on encryption type and operation mode
        self.update_key_section()
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select File")
        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            self.file_label.config(text=f"Selected: {filename}")
    
    def browse_key_file(self):
        operation = self.operation_mode.get()
        file_type = "Public" if operation == "encrypt" else "Private"
        file_extension = "*.pem"
        
        key_path = filedialog.askopenfilename(
            title=f"Select {file_type} Key File",
            filetypes=[(f"{file_type} Key", file_extension)]
        )
        
        if key_path:
            self.key_file_path = key_path
            filename = os.path.basename(key_path)
            self.key_file_label.config(text=f"Selected: {filename}")
    
    def generate_rsa_keys(self):
        # Ask user for key size
        key_sizes = {
            "2048 bits (recommended)": 2048,
            "4096 bits (stronger but slower)": 4096
        }
        key_size_str = tk.simpledialog.askstring(
            "Key Size",
            "Select RSA key size:",
            initialvalue="2048 bits (recommended)"
        )
        
        if not key_size_str or key_size_str not in key_sizes:
            return
        
        key_size = key_sizes[key_size_str]
        
        # Generate keys
        try:
            self.status_label.config(text="Generating RSA keys...")
            self.root.update()
            
            private_key, public_key = CryptoUtils.generate_rsa_key_pair(key_size)
            
            # Ask user where to save private key
            private_path = filedialog.asksaveasfilename(
                title="Save Private Key",
                defaultextension=".pem",
                filetypes=[("PEM Files", "*.pem")],
                initialfile="private_key.pem"
            )
            
            if not private_path:
                self.status_label.config(text="Key generation cancelled")
                return
            
            # Ask user where to save public key
            public_path = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".pem",
                filetypes=[("PEM Files", "*.pem")],
                initialfile="public_key.pem"
            )
            
            if not public_path:
                self.status_label.config(text="Key generation cancelled")
                return
            
            # Save keys
            CryptoUtils.save_rsa_keys(private_key, public_key, private_path, public_path)
            
            self.status_label.config(text="RSA keys generated successfully")
            messagebox.showinfo("Success", "RSA keys generated and saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")
            self.status_label.config(text="Error generating RSA keys")
    
    def validate_inputs(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No file selected")
            return False
        
        encryption_type = self.encryption_type.get()
        operation = self.operation_mode.get()
        
        if encryption_type == "AES":
            key = self.key_entry.get()
            if not key:
                messagebox.showerror("Error", "AES key is required")
                return False
            
            key_length = len(key.encode('utf-8'))
            if key_length not in [16, 24, 32]:
                messagebox.showerror("Error", f"AES key must be 16, 24, or 32 bytes long (current: {key_length} bytes)")
                return False
        
        elif encryption_type in ["RSA", "Hybrid"]:
            if not self.key_file_path:
                key_type = "public" if operation == "encrypt" else "private"
                messagebox.showerror("Error", f"No RSA {key_type} key file selected")
                return False
        
        return True
    
    def process_file(self):
        if not self.validate_inputs():
            return
        
        # Ask user where to save the output file
        operation = self.operation_mode.get()
        file_extension = os.path.splitext(self.selected_file)[1]
        
        if operation == "encrypt":
            default_filename = f"encrypted-{os.path.basename(self.selected_file)}"
        else:
            # Strip "encrypted-" prefix if present
            filename = os.path.basename(self.selected_file)
            if filename.startswith("encrypted-"):
                default_filename = filename[len("encrypted-"):]
            else:
                default_filename = f"decrypted-{filename}"
        
        output_path = filedialog.asksaveasfilename(
            title=f"Save {operation.capitalize()}ed File",
            defaultextension=file_extension,
            initialfile=default_filename
        )
        
        if not output_path:
            return
        
        # Disable UI during processing
        self.set_ui_state(tk.DISABLED)
        self.progress_bar["value"] = 0
        self.status_label.config(text=f"{operation.capitalize()}ing file...")
        self.root.update()
        
        # Create a thread for processing
        encryption_type = self.encryption_type.get()
        
        thread = threading.Thread(
            target=self.process_file_thread,
            args=(encryption_type, operation, output_path)
        )
        thread.daemon = True
        thread.start()
    
    def process_file_thread(self, encryption_type, operation, output_path):
        try:
            if encryption_type == "AES":
                key = self.key_entry.get()
                
                if operation == "encrypt":
                    CryptoUtils.aes_encrypt_file(
                        self.selected_file, key, output_path,
                        lambda progress: self.update_progress(progress)
                    )
                else:
                    CryptoUtils.aes_decrypt_file(
                        self.selected_file, key, output_path,
                        lambda progress: self.update_progress(progress)
                    )
            
            elif encryption_type == "RSA":
                if operation == "encrypt":
                    CryptoUtils.rsa_encrypt_file(
                        self.selected_file, self.key_file_path, output_path,
                        lambda progress: self.update_progress(progress)
                    )
                else:
                    CryptoUtils.rsa_decrypt_file(
                        self.selected_file, self.key_file_path, output_path,
                        lambda progress: self.update_progress(progress)
                    )
            
            elif encryption_type == "Hybrid":
                if operation == "encrypt":
                    CryptoUtils.hybrid_encrypt_file(
                        self.selected_file, self.key_file_path, output_path,
                        lambda progress: self.update_progress(progress)
                    )
                else:
                    CryptoUtils.hybrid_decrypt_file(
                        self.selected_file, self.key_file_path, output_path,
                        lambda progress: self.update_progress(progress)
                    )
            
            # On successful completion
            self.root.after(0, lambda: self.process_complete(True, f"File {operation}ed successfully!"))
        
        except Exception as e:
            # On error
            self.root.after(0, lambda: self.process_complete(False, str(e)))
    
    def update_progress(self, percentage):
        self.root.after(0, lambda: self.progress_bar.config(value=percentage))
    
    def process_complete(self, success, message):
        self.set_ui_state(tk.NORMAL)
        
        if success:
            self.status_label.config(text="Complete")
            messagebox.showinfo("Success", message)
        else:
            self.status_label.config(text="Error")
            messagebox.showerror("Error", message)
    
    def set_ui_state(self, state):
        # Enable/disable UI elements during processing
        self.process_button.config(state=state)
        if hasattr(self, 'key_entry'):
            self.key_entry.config(state=state)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()