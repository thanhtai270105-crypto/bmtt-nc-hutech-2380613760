import rsa
import os

class RSACipher:
    def __init__(self):
        self.key_dir = os.path.join(os.getcwd(), "cipher", "rsa", "keys")
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)

    def generate_keys(self):
        (pub_key, priv_key) = rsa.newkeys(1024)
        with open(os.path.join(self.key_dir, "publicKey.pem"), "wb") as f:
            f.write(pub_key.save_pkcs1())
        with open(os.path.join(self.key_dir, "privateKey.pem"), "wb") as f:
            f.write(priv_key.save_pkcs1())

    def load_keys(self):
        with open(os.path.join(self.key_dir, "publicKey.pem"), "rb") as f:
            pub_key = rsa.PublicKey.load_pkcs1(f.read())
        with open(os.path.join(self.key_dir, "privateKey.pem"), "rb") as f:
            priv_key = rsa.PrivateKey.load_pkcs1(f.read())
        return priv_key, pub_key

    def encrypt(self, message, key):
        return rsa.encrypt(message.encode('utf-8'), key)

    def decrypt(self, ciphertext, key):
        return rsa.decrypt(ciphertext, key).decode('utf-8')

    def sign(self, message, key):
        return rsa.sign(message.encode('utf-8'), key, 'SHA-1')

    def verify(self, message, signature, key):
        try:
            rsa.verify(message.encode('utf-8'), signature, key)
            return True
        except:
            return False