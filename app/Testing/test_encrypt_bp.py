import unittest
from Blueprints.encrypt_bp import derive_key, encrypt_data, decrypt_data

class TestEncryptionBlueprint(unittest.TestCase):
    def test_key_derivation(self):
        password = "securepassword"
        salt = b"randomsalt"
        key = derive_key(password, salt)
        self.assertEqual(len(key), 32)  # AES 256-bit key size

    def test_encryption_decryption(self):
        password = "securepassword"
        salt = b"randomsalt"
        key = derive_key(password, salt)
        original_data = "Hello, Encryption!"
        encrypted = encrypt_data(original_data, key)
        decrypted = decrypt_data(encrypted, key)
        self.assertEqual(original_data, decrypted)

if __name__ == "__main__":
    unittest.main()
