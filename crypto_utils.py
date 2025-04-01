import os
import base64
import hashlib
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Configure logging
logger = logging.getLogger(__name__)

# AES encryption key - in production, this should be securely stored
# Using environment variable with fallback
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # Generate a random key for development
    ENCRYPTION_KEY = base64.b64encode(get_random_bytes(32)).decode('utf-8')
    logger.warning("Using randomly generated encryption key. In production, set ENCRYPTION_KEY environment variable.")

def encrypt_data(data):
    """
    Encrypt data using AES-256-CBC
    
    Args:
        data (str): The data to encrypt
        
    Returns:
        dict: A dictionary containing the encrypted data, iv, and tag
    """
    try:
        # Convert string data to bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Decode the base64 key
        key = base64.b64decode(ENCRYPTION_KEY)
        
        # Generate a random initialization vector
        iv = get_random_bytes(16)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the data and encrypt
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        
        # Encode binary data as base64 for storage/transmission
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        iv = base64.b64encode(iv).decode('utf-8')
        
        return {
            'ciphertext': ct,
            'iv': iv
        }
    
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_data(encrypted_data):
    """
    Decrypt data using AES-256-CBC
    
    Args:
        encrypted_data (dict): A dictionary containing the encrypted data and iv
        
    Returns:
        str: The decrypted data as a string
    """
    try:
        # Get ciphertext and iv from the dictionary
        ct = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        
        # Decode the base64 key
        key = base64.b64decode(ENCRYPTION_KEY)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        
        # Return decrypted data as string
        return pt.decode('utf-8')
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

def hash_password(password):
    """
    Create a secure hash of a password using SHA-256
    
    Args:
        password (str): The password to hash
        
    Returns:
        str: The hashed password
    """
    try:
        # Add a static salt - in production, use a per-user salt
        salt = os.environ.get('PASSWORD_SALT', 'cybersecurity_platform_salt')
        
        # Create a hash with salt
        dk = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password.encode('utf-8'),
            salt=salt.encode('utf-8'),
            iterations=100000
        )
        
        # Return base64 encoded hash
        return base64.b64encode(dk).decode('utf-8')
    
    except Exception as e:
        logger.error(f"Password hashing error: {str(e)}")
        raise

def verify_password(stored_hash, provided_password):
    """
    Verify a password against a stored hash
    
    Args:
        stored_hash (str): The previously stored hash
        provided_password (str): The password to verify
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    try:
        # Hash the provided password
        calculated_hash = hash_password(provided_password)
        
        # Compare hashes using constant-time comparison (to prevent timing attacks)
        return hashlib.compare_digest(stored_hash, calculated_hash)
    
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False

def generate_secure_token(length=32):
    """
    Generate a secure random token
    
    Args:
        length (int): The desired token length (default: 32)
        
    Returns:
        str: A secure random token
    """
    try:
        token_bytes = get_random_bytes(length)
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8')
    
    except Exception as e:
        logger.error(f"Token generation error: {str(e)}")
        raise

def hash_file(file_data):
    """
    Create a SHA-256 hash of file data
    
    Args:
        file_data (bytes): The file data to hash
        
    Returns:
        str: The file hash as a hexadecimal string
    """
    try:
        return hashlib.sha256(file_data).hexdigest()
    
    except Exception as e:
        logger.error(f"File hashing error: {str(e)}")
        raise
