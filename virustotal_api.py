import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

urlVT = "https://www.virustotal.com/api/v3/urls" #input(str("URL:"))

urlToCheck = input(str("URL:"))

def getAnalysis(urlToAnalyse):
    url = "https://www.virustotal.com/api/v3/urls/" 
    headers = {"x-apikey": API_KEY,
                "accept": "application/json"} #json is a way to store store. so it is telling it to send the data in json format.
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print (1)
        print(response.json())
    else:
        print("The URL is not available!")
getAnalysis(urlToCheck)

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
        
        json_data = response.json()
        urlID = json_data["data"]["links"]["self"]
        print(urlID)      
    else:
        print(response)

urlCheck(urlToCheck)