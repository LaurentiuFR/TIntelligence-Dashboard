from datetime import datetime
import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

urlVT = "https://www.virustotal.com/api/v3/urls" #input(str("URL:"))

urlToCheck = input(str("URL:"))

def getAnalysis(urlToAnalyse):
    url = urlToAnalyse
    headers = {"x-apikey": API_KEY,
                "accept": "application/json"} #json is a way to store store. so it is telling it to send the data in json format.
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        #print (1)
        data = response.json()
        stats = data["data"]["attributes"]["stats"]
        maliciousCount = stats["malicious"]
        suspectCount = stats["suspicious"]
        undetected = stats["undetected"]
        harmless = stats["harmless"]
        timeout = stats["timeout"]
        confirmedTimeout = stats["confirmed-timeout"]
        failure = stats["failure"]
        typeUnsupported = stats["type-unsupported"]

        dateNumber = data["data"]["attributes"]["date"]

        date = 
        time = 

        if maliciousCount > 0:
            print("The URL is malicious!")
        elif suspectCount > 0:
            print("The URL is suspicious!")
        elif undetected > 0:
            print("The URL is undetected!")
        elif harmless > 0:
            print("The URL is harmless!")

        print(response.json())

    else:
        print("The URL is not available!")


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
        getAnalysis(urlID)
    else:
        print(response)

urlCheck(urlToCheck)