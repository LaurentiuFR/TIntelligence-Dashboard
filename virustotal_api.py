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

<<<<<<< Updated upstream
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

=======
def analyseData(data):
    print(1)
    stats = data["data"]["attributes"]["stats"]
    maliciousCount = stats["malicious"]
    suspectCount = stats["suspicious"]
    undetected = stats["undetected"]
    harmless = stats["harmless"]
    timeout = stats["timeout"]
    confirmedTimeout = stats["confirmed_timeout"]
    failure = stats["failure"]
    typeUnsupported = stats["type_unsupported"]
    dateNumber = data["data"]["attributes"]["date"]

    # work on the formula this is a placeholder.
    if maliciousCount > 0:
        print("The URL is malicious!")
    elif suspectCount > 0:
        print("The URL is suspicious!")
    elif undetected > 0:
        print("The URL is undetected!")
    elif harmless > 0:
        print("The URL is harmless!")
>>>>>>> Stashed changes


def getAnalysis(urlToAnalyse):
    currenTime = datetime.now()
    url = urlToAnalyse
    headers = {"x-apikey": API_KEY,
                "accept": "application/json"} #json is a way to store store. so it is telling it to send the data in json format.
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
<<<<<<< Updated upstream
        print("Result: ")
=======
        data = response.json()

        analyseData(data)

        timeTaken = datetime.now() - currenTime
        timeTakenSeconds = timeTaken.total_seconds()

        if timeTakenSeconds < 1:
            miliseconds = timeTakenSeconds * 1000
            print(f"It took {miliseconds:.2f} ms")
        elif timeTakenSeconds > 60:
            minutes = timeTakenSeconds / 60
            print(f"It took {minutes:.2f} mins")
            if timeTakenSeconds > 1800:
                print("Timeout - took too long...")
        else:
            print(f"It took {timeTakenSeconds:.2f} seconds")

>>>>>>> Stashed changes
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
        getAnalysis(urlID)
    else:
        print("Error 1 -> (API Key not Found | Website Not Found | Server Error)")

urlCheck(urlToCheck)