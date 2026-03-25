from Crypto.Hash import SHA256

def sha3(message):
    sha256_hash = SHA256.new()
    sha256_hash.update(message)
    return sha256_hash.digest()

def main():
    text = input("Nhập chuỗi văn bản: ").encode('utf-8')
    hashed_text = sha3(text)

    print("Chuỗi văn bản đã nhập:", text.decode('utf-8'))
    print("SHA-3 Hash:", hashed_text.hex())

if __name__ == "__main__":
    main()