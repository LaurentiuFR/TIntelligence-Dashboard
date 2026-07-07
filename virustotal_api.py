from datetime import datetime
import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("API Key loaded securely!") 

urlVT = "https://www.virustotal.com/api/v3/urls" #input(str("URL:"))

urlToCheck = input(str("URL:"))

def responseTime(startingTime, finalTime):
    finalTime = (finalTime - startingTime).total_seconds()
    if finalTime < 1:
        miliseconds = finalTime * 1000
        print(f"It took {miliseconds:.2f} ms")
    elif finalTime > 60:
        minutes = finalTime / 60
        print(f"It took {minutes:.2f} mins")
        if finalTime > 1800:
            print("Timeout - took too long...")
    else:
        print(f"It took {finalTime:.2f} seconds")



def getAnalysis(urlToAnalyse):
    currenTime = datetime.now()
    url = urlToAnalyse
    headers = {"x-apikey": API_KEY,
                "accept": "application/json"} #json is a way to store store. so it is telling it to send the data in json format.
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("Result: ")
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