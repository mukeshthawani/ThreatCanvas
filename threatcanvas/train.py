import pandas as pd
import numpy as np
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class ModelTrainer:
    """A class for training and saving anomaly detection models for web traffic analysis.

    This class handles the entire pipeline of preprocessing web traffic data,
    training an Isolation Forest model for anomaly detection, and saving the
    trained models for later use.

    Attributes:
        MODEL_DIR (str): Directory path where trained models will be saved
        VECTORIZER_PATH (str): Path for saving the TF-IDF vectorizer
        SCALER_PATH (str): Path for saving the StandardScaler
        ISOLATION_FOREST_PATH (str): Path for saving the Isolation Forest model
    """

    def __init__(self):
        """Initialize ModelTrainer with model paths and create necessary directories."""
        self.MODEL_DIR = "models"
        self.VECTORIZER_PATH = os.path.join(self.MODEL_DIR, "tfidf_vectorizer.joblib")
        self.SCALER_PATH = os.path.join(self.MODEL_DIR, "scaler.joblib")
        self.ISOLATION_FOREST_PATH = os.path.join(self.MODEL_DIR, "isolation_forest.joblib")
        
        # Ensure the model directory exists
        os.makedirs(self.MODEL_DIR, exist_ok=True)

    def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess the input DataFrame by cleaning and combining features.

        Args:
            df (pd.DataFrame): Input DataFrame containing web traffic data with columns
                             'path', 'user_agent', 'method', and 'status'

        Returns:
            pd.DataFrame: Processed DataFrame with additional columns 'path_cleaned',
                         'user_agent_cleaned', and 'combined_features'
        """
        df['path_cleaned'] = df['path'].fillna('').str.lower()
        df['user_agent_cleaned'] = df['user_agent'].fillna('').str.lower()
        
        df['combined_features'] = (
            df['method'].fillna('') + ' ' +
            df['path_cleaned'] + ' ' +
            df['status'].astype(str) + ' ' +
            df['user_agent_cleaned']
        )
        return df

    def train_model(self, df: pd.DataFrame) -> None:
        """Train the anomaly detection model pipeline and save the models.

        This method processes the input data, trains a TF-IDF vectorizer,
        StandardScaler, and Isolation Forest model, and saves them to disk.

        Args:
            df (pd.DataFrame): Input DataFrame containing web traffic data

        Returns:
            None
        """
        # Preprocess the data
        df = self.preprocess_data(df)
        
        # Vectorize combined features
        tfidf = TfidfVectorizer(max_features=1000, stop_words='english')
        feature_vectors = tfidf.fit_transform(df['combined_features']).toarray()
        
        # Scale the feature vectors
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(feature_vectors)
        
        # Train Isolation Forest
        isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        isolation_forest.fit(scaled_features)
        
        # Save the models
        joblib.dump(tfidf, self.VECTORIZER_PATH)
        joblib.dump(scaler, self.SCALER_PATH)
        joblib.dump(isolation_forest, self.ISOLATION_FOREST_PATH)
        
        print("Models Saved Successfully!")

"""
if __name__ == "__main__":
    path = "../data/web-server-access-logs_10k.csv"
    df = pd.read_csv(path)
    
    trainer = ModelTrainer()
    trainer.train_model(df)
"""