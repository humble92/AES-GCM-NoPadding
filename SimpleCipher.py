from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class SimpleCipher:
    key = None
    gcm_iv_length = 12
    gcm_tag_length = 16
    algorithm = AES.MODE_GCM

    # TODO: read upc_enc_key from env.
    @classmethod
    def init_secret_key(cls):
        upc_enc_key = "sF64wUalT2XRaB/J"
        cls.key = bytes(upc_enc_key, 'utf-8')

    # Temporary usage for test
    @classmethod
    def encrypt_file(cls, fromFile, toFile):
        cls.init_secret_key()
        try:
            f = open(fromFile, "rb")
            data = f.read()
            f.close()

            nonce = get_random_bytes(cls.gcm_iv_length)
            cipher = AES.new(cls.key, cls.algorithm, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + ciphertext + tag
            result = b64encode(encrypted).decode('utf-8')

            f = open(toFile, "w")
            f.write(result)
            f.close()
        except FileNotFoundError:
            print("File not found!")

    @classmethod
    def decrypt_file(cls, fromFile, toFile):
        cls.init_secret_key()
        try:
            f = open(fromFile, "rb")
            data = f.read()
            f.close()

            d = b64decode(data)
            cipher = AES.new(cls.key, cls.algorithm, nonce=d[0:cls.gcm_iv_length])
            plaintext = cipher.decrypt_and_verify(
                d[cls.gcm_iv_length:(-1) * cls.gcm_tag_length],
                d[(-1) * cls.gcm_tag_length:]
            )

            f = open(toFile, "w")
            f.write(plaintext.decode())
            f.close()
        except FileNotFoundError:
            print("File not found!")
        except ValueError:
            print("Incorrect decryption")


# Simple test
SimpleCipher.encrypt_file("source.txt", "encrypted.txt")
SimpleCipher.decrypt_file("encrypted.txt", "final.txt")
