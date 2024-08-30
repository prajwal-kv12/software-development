from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

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
print(f"User Verification Status: {'Normal' if prediction == 0 else 'Suspicious'}")
