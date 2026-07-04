import os
from dotenv import load_dotenv

# Load the secrets from the .env file
load_dotenv()

# Securely grab the API key
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 
