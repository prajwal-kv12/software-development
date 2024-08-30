import hashlib
import random
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)


def generate_otp():
    return random.randint(100000, 999999)

def verify_otp(generated_otp, entered_otp):
    return generated_otp == entered_otp


def entity_verification_ml():
    
    X = [
        [1, 20],  
        [2, 30],  
        [3, 40],  
        [4, 25],  
        [5, 45],  
    ]
    
    
    y = [0, 0, 1, 0, 1]
    
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    
    model = KNeighborsClassifier(n_neighbors=3)
    model.fit(X_train, y_train)
    
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")
    
    
    new_user_data = [[2, 28]]  
    prediction = model.predict(new_user_data)
    return prediction


if __name__ == "__main__":
    
    stored_hashed_password = hash_password("SecurePassword123")

    
    entered_password = input("Enter your password: ")
    if not verify_password(stored_hashed_password, entered_password):
        print("Password incorrect! Access denied.")
    else:
        print("Password verified!")

    
        generated_otp = generate_otp()
        print(f"Generated OTP: {generated_otp}")

    
        entered_otp = int(input("Enter the OTP you received: "))

        if not verify_otp(generated_otp, entered_otp):
            print("Invalid OTP! Access denied.")
        else:
            print("OTP verified! Proceeding to entity verification.")

    
            prediction = entity_verification_ml()
            if prediction == 0:
                print("User verified as normal. Proceed with secure messaging.")
            else:
                print("Suspicious activity detected. Further action required.")
