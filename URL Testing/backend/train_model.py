import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

def generate_synthetic_data(num_samples=10000) -> pd.DataFrame:
    np.random.seed(42)
    half_samples = num_samples // 2
    
    # Benign data generation
    benign_data = {
        "url_length": np.random.normal(40, 15, half_samples).clip(15, 150).astype(int),
        "dots_count": np.random.poisson(1.8, half_samples).clip(1, 6).astype(int),
        "subdomain_count": np.random.poisson(0.4, half_samples).clip(0, 3).astype(int),
        "has_at": np.random.choice([0, 1], half_samples, p=[0.999, 0.001]),
        "is_https": np.random.choice([0, 1], half_samples, p=[0.12, 0.88]),
        "has_ip": np.random.choice([0, 1], half_samples, p=[0.9999, 0.0001]),
        "is_shortened": np.random.choice([0, 1], half_samples, p=[0.99, 0.01]),
        "has_suspicious_keyword": np.random.choice([0, 1], half_samples, p=[0.98, 0.02]),
        "is_homograph": np.random.choice([0, 1], half_samples, p=[0.999, 0.001]),
        "special_chars_count": np.random.poisson(2.5, half_samples).clip(0, 15).astype(int),
        "has_password_input": np.random.choice([0, 1], half_samples, p=[0.92, 0.08]),
        "brand_impersonation_count": np.random.poisson(0.1, half_samples).clip(0, 2).astype(int),
        "has_hidden_elements": np.random.choice([0, 1], half_samples, p=[0.94, 0.06]),
        "is_phishing": np.zeros(half_samples, dtype=int)
    }
    
    # Phishing data generation
    phishing_data = {
        "url_length": np.random.normal(95, 30, half_samples).clip(20, 300).astype(int),
        "dots_count": np.random.poisson(4.2, half_samples).clip(1, 12).astype(int),
        "subdomain_count": np.random.poisson(2.3, half_samples).clip(0, 8).astype(int),
        "has_at": np.random.choice([0, 1], half_samples, p=[0.85, 0.15]),
        "is_https": np.random.choice([0, 1], half_samples, p=[0.55, 0.45]),
        "has_ip": np.random.choice([0, 1], half_samples, p=[0.91, 0.09]),
        "is_shortened": np.random.choice([0, 1], half_samples, p=[0.78, 0.22]),
        "has_suspicious_keyword": np.random.choice([0, 1], half_samples, p=[0.25, 0.75]),
        "is_homograph": np.random.choice([0, 1], half_samples, p=[0.94, 0.06]),
        "special_chars_count": np.random.poisson(9.0, half_samples).clip(0, 35).astype(int),
        "has_password_input": np.random.choice([0, 1], half_samples, p=[0.60, 0.40]),
        "brand_impersonation_count": np.random.poisson(1.2, half_samples).clip(0, 4).astype(int),
        "has_hidden_elements": np.random.choice([0, 1], half_samples, p=[0.75, 0.25]),
        "is_phishing": np.ones(half_samples, dtype=int)
    }
    
    df_benign = pd.DataFrame(benign_data)
    df_phishing = pd.DataFrame(phishing_data)
    
    df = pd.concat([df_benign, df_phishing], ignore_index=True)
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def train_model():
    print("Generating synthetic dataset...")
    df = generate_synthetic_data(12000)
    
    feature_cols = [
        "url_length", "dots_count", "subdomain_count", "has_at", "is_https", 
        "has_ip", "is_shortened", "has_suspicious_keyword", "is_homograph", 
        "special_chars_count", "has_password_input", "brand_impersonation_count", 
        "has_hidden_elements"
    ]
    
    X = df[feature_cols]
    y = df["is_phishing"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature Importance
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\nFeature Importances:")
    for f in range(X.shape[1]):
        print(f"{f + 1}. {feature_cols[indices[f]]} ({importances[indices[f]]:.4f})")
    
    # Save the model
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(backend_dir, "model.joblib")
    joblib.dump(model, model_path)
    print(f"\nModel successfully saved to {model_path}")
    
    # Save feature names for reference
    feature_names_path = os.path.join(backend_dir, "features.joblib")
    joblib.dump(feature_cols, feature_names_path)

if __name__ == "__main__":
    train_model()
