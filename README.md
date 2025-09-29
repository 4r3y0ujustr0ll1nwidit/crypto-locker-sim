# crypto-locker-sim
import hashlib

def generate_sha256_hash(data_string):
    """
    Generates a SHA-256 cryptographic hash for a given string.
    This is commonly used for data integrity checks and in blockchains.
    """
    # 1. Encode the string to bytes (hashing functions require byte input)
    encoded_data = data_string.encode('utf-8')

    # 2. Create a new SHA-256 hash object
    hash_object = hashlib.sha256()

    # 3. Update the hash object with the data
    hash_object.update(encoded_data)

    # 4. Get the hexadecimal representation of the hash
    hex_hash = hash_object.hexdigest()

    return hex_hash

# --- Usage Example ---

# The data we want to hash (e.g., a block of a blockchain)
data = "Hello world! This is a test of SHA-256 hashing."

# Generate the hash
my_hash = generate_sha256_hash(data)

# Print the results
print(f"Original Data: {data}")
print("-" * 50)
print(f"SHA-256 Hash:  {my_hash}")

# Demonstrating data integrity: even a small change completely alters the hash
data_minor_change = "Hello world! This is a test of SHA-256 hashing.." # Added one dot
my_hash_changed = generate_sha256_hash(data_minor_change)

print("-" * 50)
print(f"Data with minor change: {data_minor_change}")
print(f"New SHA-256 Hash: {my_hash_changed}")



