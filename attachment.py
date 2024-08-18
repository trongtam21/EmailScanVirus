import email
import requests
import json
import time
from termcolor import colored

def extract_base64_attachments(eml_file):
    attachments = []
    
    with open(eml_file, 'r') as file:
        msg = email.message_from_file(file)
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            content_disposition = part.get('Content-Disposition', None)
            if content_disposition and 'attachment' in content_disposition:
                filename = part.get_filename()
                
                if part.get('Content-Transfer-Encoding') == 'base64':
                    base64_data = part.get_payload(decode=True)
                    attachments.append((filename, base64_data))
                    
    return attachments

def check_binary_file(api_key, binary_data):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file': ('file.bin', binary_data)}
    params = {'apikey': api_key}
    
    response = requests.post(url, files=files, params=params)
    response_json = json.loads(response.text)
    
    if response_json['response_code'] == 1:
        scan_id = response_json["scan_id"]
        countdown_timer(30)
        
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params2 = {'apikey': api_key, 'resource': scan_id}
        response2 = requests.get(url, params=params2)
        response_json2 = json.loads(response2.text)
        
        if response_json2['response_code'] == 1:
            results_list = []
            for vendor, data in response_json2['scans'].items():
                result = data['result'] if data['result'] else "Undetected"
                
                if result == "Undetected":
                    results_list.append(colored(f"{vendor}: {result}", "green"))
                else:
                    results_list.append(colored(f"{vendor}: {result}", "red"))
            
            print(f"=== Security vendors' analysis for attachment ===")
            print(" | ".join(results_list))
            
            if response_json2['positives'] > 0:
                return "Malicious"
            else:
                return "Not Malicious"
        else:
            return "Not Found in Database"
    else:
        return "Error occurred"

def process_eml_file(eml_file, api_key):
    attachments = extract_base64_attachments(eml_file)
    
    for i, (filename, base64_data) in enumerate(attachments):
        print(f"Checking attachment '{filename}'...")
        result = check_binary_file(api_key, base64_data)
        print(f"Attachment '{filename}' result: {result}")

def countdown_timer(seconds):
    for i in range(seconds, 0, -1):
        print(f"Waiting... {i} seconds remaining", end="\r")
        time.sleep(1)
    print("Checking report...\n")