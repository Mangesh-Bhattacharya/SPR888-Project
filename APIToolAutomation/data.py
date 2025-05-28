import os
import csv
import re

# Constants
DATASET_FOLDER = "datasets"
OUTPUT_DIR = "AITrainingFiles"
CSV_FILE = os.path.join(OUTPUT_DIR, "ioc_findings.csv")
os.makedirs(OUTPUT_DIR, exist_ok=True)

IOC_FILE_KEYWORDS = {
    'ips': ['ip'],
    'attacker_name': ['attacker', 'apt'],
    'url': ['url', 'phish', 'c2'],
    'email': ['email'],
    'domain': ['domain'],
    'hash': ['hash', 'md5', 'sha1', 'sha256']
}

_csv_initialized = False

def get_user_input():
    ioc_type_input = input("Enter IoC type (ips, attacker_name, url, email, domain, hash): ").strip().lower()
    ioc_value = input("Enter the IoC value: ").strip()

    if ioc_type_input not in IOC_FILE_KEYWORDS:
        print("Invalid IoC type. Use one of: ips, attacker_name, url, email, domain, hash")
        exit()

    return ioc_type_input, ioc_value

def get_relevant_files(ioc_type):
    keywords = IOC_FILE_KEYWORDS[ioc_type]
    relevant_files = []

    for root, dirs, files in os.walk(DATASET_FOLDER):
        for file in files:
            if any(keyword in file.lower() for keyword in keywords):
                relevant_files.append(os.path.join(root, file))

    return relevant_files

def search_ioc_in_file(file_path, ioc_value):
    pattern = re.compile(rf'\b{re.escape(ioc_value)}\b', re.IGNORECASE)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return any(pattern.search(line) for line in f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return False

def check_ioc_in_datasets(ioc_value, files):
    matched_files = []
    for file_path in files:
        if search_ioc_in_file(file_path, ioc_value):
            matched_files.append(os.path.basename(file_path))
    return matched_files

def write_result_to_csv(ioc_type, ioc_value, matched_files):
    global _csv_initialized
    mode = 'w' if not _csv_initialized else 'a'

    with open(CSV_FILE, mode, newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not _csv_initialized:
            writer.writerow(["IoC Type", "IoC Value", "Source", "Result"])
            _csv_initialized = True

        if matched_files:
            for file in matched_files:
                writer.writerow([ioc_type, ioc_value, file, "Found"])
        else:
            writer.writerow([ioc_type, ioc_value, "None", "Not Found"])

def main():
    ioc_type, ioc_value = get_user_input()
    relevant_files = get_relevant_files(ioc_type)
    matched_files = check_ioc_in_datasets(ioc_value, relevant_files)

    if matched_files:
        print(f"{ioc_value} is a {ioc_type} and is found in {', '.join(matched_files)}")
    else:
        print(f"{ioc_value} is a {ioc_type} and is not found in any dataset")

    write_result_to_csv(ioc_type, ioc_value, matched_files)

if __name__ == "__main__":
    main()
