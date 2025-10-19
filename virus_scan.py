import os
import requests

SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def update_file(file_path):
    
    params = {'apikey': API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(SCAN_URL, files=files, params=params)
    result = response.json()
    return result['scan_id']


def scan_file(file_path):
    resource = update_file(file_path)
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(REPORT_URL, params=params)
    if not response:
        raise Exception("Unexpected error in response")
    if response.status_code == 200:
        result = response.json()
        if result['positives']>0:
            print("virus detected")
        else:
            print("virus has not been detected, file safe")
        return result['positives']>0
    else:
        raise Exception("unexpected status code:", response.status_code)


def scan_folder_files(folder_path):
    for item in os.listdir(folder_path):
        full_path = os.path.join(folder_path, item)
        if os.path.isdir(full_path):
            scan_folder_files(full_path)
        else:
            print(f"scanning {item}")
            scan_file(full_path)