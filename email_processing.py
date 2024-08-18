from email import policy
from email.parser import BytesParser
import os
def get_api_key(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return file.read().strip()
    else:
        api_key = input("API KEY VIRUS TOTAL: ")
        with open(file_path, 'w') as file:
            file.write(api_key)
        return api_key

def select_file(file_name):
    print(f"Processing file: {file_name}")

def extract_email_addresses(file_path):
    try:
        with open(file_path, 'rb') as file:
            msg = BytesParser(policy=policy.default).parse(file)

        from_address = msg['From']
        to_address = msg['To']

        # In ra kết quả
        print(f"From: {from_address}")
        print(f"To: {to_address}")
    except Exception as e:
        print(f"An error occurred: {e}")
