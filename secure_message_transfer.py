import os
import hashlib
import random
from Crypto.Cipher import AES
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.datasets import load_iris

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = message + (16 - len(message) % 16) * ' '
    encrypted_message = cipher.encrypt(padded_message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message).decode().strip()
    return decrypted_message

def user_authentication(stored_password_hash):
    password = input("Enter your password: ") 
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash == stored_password_hash:
        print("Password verified!")
        return True
    else:
        print("Password incorrect!")
        return False

def generate_otp():
    otp = random.randint(100000, 999999)
    print(f"OTP for validation: {otp}")
    return otp

def verify_otp(generated_otp):
    user_otp = int(input("Enter the OTP: "))
    if user_otp == generated_otp:
        print("OTP verified!")
        return True
    else:
        print("Incorrect OTP!")
        return False

def entity_verification():
    iris = load_iris()
    X = iris.data
    y = iris.target
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = LogisticRegression(max_iter=200)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test) * 100
    print(f"Model Accuracy: {accuracy:.2f}%")
    
    new_user_data = [X_test[0]]
    predicted_label = model.predict(new_user_data)
    
    if predicted_label == [0]:
        print("User verified as normal.")
    else:
        print("User verification failed.")

def main():
    secret_key = hashlib.sha256("mysecretkey".encode()).digest()
    message = "This is a secret message."
    
    encrypted_message = encrypt_message(message, secret_key)
    print(f"Encrypted: {encrypted_message}")
    
    decrypted_message = decrypt_message(encrypted_message, secret_key)
    print(f"Decrypted: {decrypted_message}")

    stored_password_hash = hashlib.sha256("SecurePassword123".encode()).hexdigest()
    
    if user_authentication(stored_password_hash):
        otp = generate_otp()
        if verify_otp(otp):
            entity_verification()
        else:
            print("Failed OTP verification. Access denied.")
    else:
        print("Authentication failed. Access denied.")

if __name__ == "__main__":
    main()
