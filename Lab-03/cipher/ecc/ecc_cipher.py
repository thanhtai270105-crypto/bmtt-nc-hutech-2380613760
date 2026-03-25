import ecdsa
import os

# ================= TẠO THƯ MỤC LƯU KEY =================
if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')


class ECCCipher:
    def __init__(self):
        pass

    # ================= GENERATE KEYS =================
    def generate_keys(self):
        # Tạo khóa riêng
        sk = ecdsa.SigningKey.generate()

        # Tạo khóa công khai
        vk = sk.verifying_key

        # Lưu private key
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(sk.to_pem())

        # Lưu public key
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(vk.to_pem())

    # ================= LOAD KEYS =================
    def load_keys(self):
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())

        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())

        return sk, vk

    # ================= SIGN =================
    def sign(self, message, key):
        # ký bằng private key
        return key.sign(message.encode('utf-8'))

    # ================= VERIFY =================
    def verify(self, message, signature, key):
        try:
            # verify bằng public key
            return key.verify(signature, message.encode('utf-8'))
        except ecdsa.BadSignatureError:
            return False