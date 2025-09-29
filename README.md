from cryptography.fernet import Fernet
import os

# 1. Key Generation
def generate_key():
    """
    Generates a new AES symmetric encryption key.
    This key must be securely shared between the sender and receiver.
    """
    # Fernet is an opinionated format that uses AES 256 in CBC mode, 
    # and provides built-in integrity checking.
    # It's an excellent choice for general-purpose symmetric encryption.
    return Fernet.generate_key()

# 2. Encryption
def encrypt_message(message: bytes, key: bytes) -> bytes:
    """Encrypts a byte message using the provided key."""
    f = Fernet(key)
    # The encrypt() method returns the encrypted data (ciphertext) 
    # along with the Initialization Vector (IV) and a Message Authentication Code (MAC)
    # all bundled together into a single token.
    encrypted_data = f.encrypt(message)
    return encrypted_data

# 3. Decryption
def decrypt_message(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts a byte message using the provided key. 
    It will raise an exception if the key is wrong or the data is tampered with.
    """
    f = Fernet(key)
    # The decrypt() method checks the integrity/authenticity before decrypting.
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data

# --- Usage Example ---

# Generate the shared secret key
secret_key = generate_key()
print(f"Generated Secret Key (share this securely): {secret_key.decode()}")
print("-" * 60)

# The message we want to encrypt (must be in bytes)
original_message = "This secret data must be protected from prying eyes!"
message_bytes = original_message.encode()

# Encrypt the message
print("Encrypting...")
ciphertext = encrypt_message(message_bytes, secret_key)
print(f"Ciphertext (Encrypted Data): {ciphertext.decode()}")
print("-" * 60)

# Decrypt the message
print("Decrypting...")
try:
    decrypted_bytes = decrypt_message(ciphertext, secret_key)
    decrypted_message = decrypted_bytes.decode()
    
    print(f"Decrypted Message: {decrypted_message}")

    # Verify
    if original_message == decrypted_message:
        print("\n✅ Success! Encryption and Decryption verified.")
    else:
        print("\n❌ Failure! Messages do not match.")

except Exception as e:
    print(f"\n❌ Decryption failed. Error: {e}")
