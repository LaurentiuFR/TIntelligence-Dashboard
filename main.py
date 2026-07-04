import os
from dotenv import load_dotenv

# Load the secrets from the .env file
load_dotenv()

# Securely grab the API key
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

# Call function from virustotal_api.py

inputURL = input(str("URL: "))

#def UrlSent(url):
    # call virustotal_api class related to the URL checking 

returnedInfo = urlCheck()