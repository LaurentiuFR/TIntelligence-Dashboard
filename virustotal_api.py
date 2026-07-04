import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

urlVT = "https://www.virustotal.com/api/v3/urls" #input(str("URL:"))

urlToCheck = input(str("URL:"))

#def get_Analysis(urlID):

def urlCheck(urlToCheck): #-> Analysis ID
    # calls the api to check the url

    payload = {"url": urlToCheck}
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(urlVT,data = payload, headers=headers)
    
    if response.status_code == 200:
        #call function to analyse the ID
        print(1)
        json_data = response.json()
        json_data.type()
        #urlID = json_data[data][links][self]        
    else:
        print("The URL is not available!")

urlCheck(urlToCheck)