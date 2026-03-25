from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCCipher
app = Flask(__name__)

# ================= INIT =================
rsa_cipher = RSACipher()

# ================= GENERATE KEYS =================
@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})


# ================= ENCRYPT =================
@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json

    message = data.get('message')
    key_type = data.get('key_type')

    private_key, public_key = rsa_cipher.load_keys()

    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})

    encrypted_message = rsa_cipher.encrypt(message, key)
    encrypted_hex = encrypted_message.hex()

    return jsonify({'encrypted_message': encrypted_hex})


# ================= DECRYPT =================
@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json

    ciphertext_hex = data.get('ciphertext')
    key_type = data.get('key_type')

    private_key, public_key = rsa_cipher.load_keys()

    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})

    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_message = rsa_cipher.decrypt(ciphertext, key)

    return jsonify({'decrypted_message': decrypted_message})


# ================= SIGN =================
@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign_message():
    data = request.json

    message = data.get('message')

    private_key, _ = rsa_cipher.load_keys()

    signature = rsa_cipher.sign(message, private_key)
    signature_hex = signature.hex()

    return jsonify({'signature': signature_hex})


# ================= VERIFY =================
@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify_signature():
    data = request.json

    message = data.get('message')
    signature_hex = data.get('signature')

    public_key, _ = rsa_cipher.load_keys()

    signature = bytes.fromhex(signature_hex)

    is_verified = rsa_cipher.verify(message, signature, public_key)

    return jsonify({'is_verified': is_verified})

ecc_cipher = ECCCipher()
# ================= ECC CIPHER =================
from cipher.ecc.ecc_cipher import ECCCipher
# ================= GENERATE KEYS =================
@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})


# ================= SIGN =================
@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json

    message = data.get('message')

    private_key, _ = ecc_cipher.load_keys()

    signature = ecc_cipher.sign(message, private_key)
    signature_hex = signature.hex()

    return jsonify({'signature': signature_hex})


# ================= VERIFY =================
@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json

    message = data.get('message')
    signature_hex = data.get('signature')

    _, public_key = ecc_cipher.load_keys()

    signature = bytes.fromhex(signature_hex)

    is_verified = ecc_cipher.verify(message, signature, public_key)

    return jsonify({'is_verified': is_verified})

# ================= RUN =================
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)