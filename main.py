import os
import virustotal_api
from dotenv import load_dotenv

# Load the secrets from the .env file
load_dotenv()

# Securely grab the API key
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

inputURL = input(str("URL: "))


#def mainFunction():
    #inputChoice = 1 (choice to analyse an url) && urlChoice
    #call function to analyse from virustotal_api.py