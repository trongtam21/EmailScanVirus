import re
import email
import requests
import base64
from termcolor import colored
def extract_email_content(file_path):
    with open(file_path, 'r') as file:
        msg = email.message_from_file(file)
    
    # Kiểm tra nếu email là dạng multipart
    if msg.is_multipart():
        # Nếu là multipart, lấy nội dung từ từng phần
        for part in msg.walk():
            # Kiểm tra xem phần này có phải là văn bản không
            if part.get_content_type() == 'text/plain' or part.get_content_type() == 'text/html':
                # Kiểm tra phương thức mã hóa
                if part['Content-Transfer-Encoding'] == 'base64':
                    # Decode nội dung base64
                    payload = base64.b64decode(part.get_payload()).decode('utf-8')
                else:
                    payload = part.get_payload(decode=True).decode('utf-8')
                
                return payload
    else:
        # Nếu không phải là multipart, lấy nội dung văn bản
        if msg['Content-Transfer-Encoding'] == 'base64':
            return base64.b64decode(msg.get_payload()).decode('utf-8')
        else:
            return msg.get_payload(decode=True).decode('utf-8')
def extract_links(text):
    # Biểu thức chính quy để tìm các liên kết URL
    url_pattern = re.compile(r'https?://\S+')
    return url_pattern.findall(text)
def check_url_with_virustotal(api_key, url):
    endpoint = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'x-apikey': api_key
    }

    # Encode URL in base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Check URL
    response = requests.get(f'{endpoint}/{url_id}', headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        # Check result
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            output = colored(f"URL might be fraudulent!", 'red')
            return output
        else:
            output = colored(f"URL is safe.", 'green')
            return output
    else:
        output = 'Website not working (With status code : ' + " " + str(response.status_code) + ")"
        return output
def check_phishing_link(url):
    api_url = 'https://api.chongluadao.vn/v1/safecheck'
    data = {'url': url}
    
    try:
        response = requests.post(api_url, json=data)
        response.raise_for_status()
        
        result = response.json().get('type', 'nodata')
        
        if result == 'safe':
            output = colored(f"Website {url} is safe.", 'green')
            return output
        elif result == 'unsafe':
            output = colored(f"This website may be unsafe according to community reviews.", 'red')
            return output
        elif result == 'nodata':
            output = "Not found in Chongluadao.vn database and Google Safe Browsing API"
            return output
        else:
            output = "Could not determine the status of the website."
            return output
    except requests.RequestException as e:
        output = 'Website not working (With status code : ' + " " + str(response.status_code) + ")"
