from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

class Configure(BaseModel):
    """Configuration class for managing environment variables and API settings.

    This class uses Pydantic BaseModel to handle configuration settings for Azure OpenAI and Mem0. 
    It loads environment variables from a .env file and provides
    type-safe access to these configurations.

    Attributes:
        AZURE_DEPLOYMENT (str): Azure OpenAI deployment name
        AZURE_ENDPOINT (str): Azure OpenAI endpoint URL
        AZURE_API_KEY (str): Azure OpenAI API key
        AZURE_API_VERSION (str): Azure OpenAI API version, defaults to "2023-05-15"
        MODEL_NAME (str): Name of the AI model to use, defaults to "gpt-4o"

        MEM0_API_KEY (str): Mem0 API key for accessing the memory storage service
    """
    AZURE_DEPLOYMENT: str = os.getenv("AZURE_DEPLOYMENT", None)
    AZURE_ENDPOINT: str = os.getenv("AZURE_ENDPOINT", None)
    AZURE_API_KEY: str = os.getenv("AZURE_API_KEY")
    AZURE_API_VERSION: str = os.getenv("AZURE_API_VERSION", "2023-05-15")
    MODEL_NAME: str = os.getenv("MODEL_NAME", "gpt-4o")

    MEM0_API_KEY: str = os.getenv("MEM0_API_KEY")
    
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

config = Configure()