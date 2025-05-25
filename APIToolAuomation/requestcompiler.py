import os
import requests
import re
import csv
from dotenv import load_dotenv

load_dotenv() #Getting variables from the environment (api keys,potentiall ai input)

#Creating the Output File for AI ingestion
OUTPUT_DIR = "AITrainingFiles"
CSV_FILE = os.path.join(OUTPUT_DIR, "ioc_findings.csv")

#Ensuring that Output Directory Exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

_csv_initialized = False  #Global state for writing header only once

#Saving the finding to a CSV file, overwriting on first write
def save_findings(ioc_type: str, ioc_value: str, source: str, result: str):
    global _csv_initialized

    mode = "w" if not _csv_initialized else "a"
    with open(CSV_FILE, mode, newline='', encoding="utf-8") as file:
        writer = csv.writer(file)
        if not _csv_initialized:
            writer.writerow(["IoC Type", "IoC Value", "Source", "Result"])
            _csv_initialized = True
        writer.writerow([ioc_type, ioc_value, source, result])

#VirusTotal IP checking
def query_virustotal_ip(ip_address: str) -> str:
    vtapi_key = os.getenv("VT_API_KEY")
    if not vtapi_key:
        raise ValueError("VirusTotal API Key not found in environment variables.")
#Compiling the response per VT API
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": vtapi_key
    }
#Getting the response
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        error_msg = f"Error {response.status_code}: {response.text}"
        save_findings("IP", ip_address, "VirusTotal", error_msg)
        return error_msg

    data = response.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    reputation = data.get("reputation", "N/A")
    analysis_results = data.get("last_analysis_results", {})

#Defining detection variables to make the response file more summarized
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

#List detection engines that matched
    flagged_engines = []
    for engine, details in analysis_results.items():
        if details.get("category") in ("malicious", "suspicious"):
            flagged_engines.append(f"{engine}: {details.get('result')}")

#Composing summary
    summary = (
        f"Detection Ratio: {malicious + suspicious}/{total} "
        f"(Malicious: {malicious}, Suspicious: {suspicious}, "
        f"Harmless: {harmless}, Undetected: {undetected}) | "
        f"Reputation: {reputation}\n"
        f"Flagged by: {', '.join(flagged_engines) if flagged_engines else 'None'}"
    )

#Saving the result into the CSV
    save_findings("IP", ip_address, "VirusTotal", summary)

    return summary

#Classifier function to detect what type of IoC was provided
def classifier(ioc: str):
    ioc = ioc.strip() #Removing any spaces

#Variables to detect IoC pattern
    ip_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    email_pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
    
#If conditions to execute functions based on IoC type
    if ip_pattern.match(ioc):
        print("Detected IP address.")
        result = query_virustotal_ip(ioc)
        print(result)
    elif hash_pattern.match(ioc):
        print("Detected file hash. [Placeholder]")
        save_findings("Hash", ioc, "Placeholder", "No lookup implemented.")
    elif domain_pattern.match(ioc):
        print("Detected domain. [Placeholder]")
        save_findings("Domain", ioc, "Placeholder", "No lookup implemented.")
    elif email_pattern.match(ioc):
        print("Detected email. [Placeholder]")
        save_findings("Email", ioc, "Placeholder", "No lookup implemented.")
    else:
        print("Detected attacker name or unknown type. [Placeholder]")
        save_findings("AttackerName", ioc, "Placeholder", "No lookup implemented.")
#Calling main function
if __name__ == "__main__":
    ioc_input = input("Enter an IoC (IP, hash, domain, email, or attacker name): ") #Modify to pass the input from AI
    classifier(ioc_input)