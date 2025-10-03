import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.impute import SimpleImputer
import joblib
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import os # --- DEBUG ---

# --- DEBUG ---
print("--- Script execution started. ---")

def train_from_crawler_output(csv_path='features.csv'):
    # --- DEBUG ---
    print(f"--- Function train_from_crawler_output called. Looking for '{csv_path}' ---")
    
    try:
        # --- DEBUG ---
        print(f"Current working directory: {os.getcwd()}")
        print(f"Checking if file exists at path: {os.path.abspath(csv_path)}")
        if not os.path.exists(csv_path):
            print(f"FATAL ERROR: The file '{csv_path}' does not exist at the expected location.")
            return

        print(f"Loading data from '{csv_path}'...")
        df = pd.read_csv(csv_path)
        print("Data loaded successfully.")
        
        # --- DEBUG ---
        print("DataFrame Info:")
        df.info()
        print("\nFirst 3 rows of data:")
        print(df.head(3))

        # --- Feature Selection and Preparation ---
        print("\n--- Starting data preparation... ---")
        if 'label' not in df.columns:
            print("FATAL ERROR: Target column 'label' not found in the CSV.")
            return

        target = df['label']
        numeric_features = df.select_dtypes(include=np.number)
        
        if 'label' in numeric_features.columns:
            numeric_features = numeric_features.drop(columns=['label'])

        print(f"Identified {len(numeric_features.columns)} numeric features.")

        # --- Handle Missing Values ---
        print("Handling missing values using median imputation...")
        imputer = SimpleImputer(strategy='median')
        X_imputed = imputer.fit_transform(numeric_features)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_imputed, target, test_size=0.25, random_state=42, stratify=target
        )
        print("Data split into training and testing sets.")

        # --- Model Training ---
        print("\n--- Starting model training... ---")
        model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight='balanced', n_jobs=-1, max_depth=20, min_samples_leaf=5)
        model.fit(X_train, y_train)
        print("Model training complete.")

        # --- Model Evaluation ---
        print("\n" + "="*50)
        print("--- MODEL EVALUATION RESULTS ---")
        y_pred = model.predict(X_test)
        report_str = classification_report(y_test, y_pred, target_names=['Benign', 'Phishing'])
        print("\nClassification Report:")
        print(report_str)
        
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix (True vs. Predicted):")
        print(cm)
        print("="*50)
        
        # --- Save Artifacts ---
        model_filename = 'url_classifier_model_v2.joblib'
        joblib.dump(model, model_filename)
        print(f"\nSUCCESS: Trained model saved as '{model_filename}'")
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Phishing'], yticklabels=['Benign', 'Phishing'])
        plt.xlabel('Predicted Label')
        plt.ylabel('True Label')
        plt.title('Confusion Matrix for URL Classifier (Crawler Data)')
        confusion_matrix_path = 'confusion_matrix_v2.png'
        plt.savefig(confusion_matrix_path)
        print(f"SUCCESS: Confusion matrix plot saved as '{confusion_matrix_path}'")

    except Exception as e:
        # --- DEBUG ---
        print("\n" + "#"*60)
        print("AN UNEXPECTED ERROR OCCURRED. The script did not complete.")
        print(f"ERROR DETAILS: {e}")
        print("#"*60)


if __name__ == '__main__':
    # --- DEBUG ---
    print("--- __name__ == '__main__' block entered. Calling function... ---")
    train_from_crawler_output()
    # --- DEBUG ---
    print("--- Script execution finished. ---")