from Crypto.Cipher import AES
import base64

key = b'This is a key123'
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
plaintext = b'This is a secret message.'
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
decrypted_text = cipher.decrypt(ciphertext)

print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {decrypted_text.decode()}")
