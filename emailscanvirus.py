import argparse
from file_utils import select_file, file_handling
from attachment import process_eml_file
from termcolor import colored
from ip_processing import check_ip
from email_processing import extract_email_addresses, select_file, get_api_key
from content_processing import extract_email_content, extract_links, check_url_with_virustotal, check_phishing_link
def main():
    parser = argparse.ArgumentParser(description="================================ Scan email files for viruses ================================ ", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file", metavar="<file>", required=False, help="Select file (only file eml)")
    args = parser.parse_args()
    file_name = args.file
    
    api_key_file = 'api_key.txt'
    api_key = get_api_key(api_key_file)
    if file_name:
        select_file(file_name)
        # Sử dụng api_key ở đây
        print(f"Using API key: {api_key}")
        print(extract_email_addresses(file_name))
    else:
        print("Use -h or --help for assistance")
    
    print("\n============================= IP MALICIOUS CHECK =============================")
    output_ip_check = []
    ip_address = file_handling(file_name)
    if ip_address:
        result = check_ip(ip_address, api_key)
        #print(result)
        malicious_value = result.get('Malicious')
        Suspicious_value = result.get('Suspicious')
        Undetected_value = result.get('Undetected')
        Country_value = result.get('Country')
        if malicious_value is not None:
            output_ip_check.append(colored(f"Malicious: {malicious_value}", 'red'))
        if Suspicious_value is not None:
            output_ip_check.append(colored(f"Suspicious: {Suspicious_value}", 'yellow'))
        if Undetected_value is not None:
            output_ip_check.append(colored(f"Undetected : {Undetected_value}", 'green'))
        if Country_value is not None:
            output_ip_check.append(colored(f"Country : {Country_value}", 'green'))
        # ouput
        print("IP ADDRESS : ", ip_address, '\n')
        print(', '.join(output_ip_check))
    print("\n============================= Content check =============================")
    print(extract_email_content(file_name))
    content = extract_email_content(file_name)
    #print(extract_links(content))
    print("\n===== From virustotal =====\n")
    for url in extract_links(content):
        result = check_url_with_virustotal(api_key, url)
        print(url ," : ", result)
    print("\n===== From Chongluadao.vn database and Google Safe Browsing API ===== \n")
    for url2 in extract_links(content):
        result = check_phishing_link(url2)
        print(url2 ," : ", result)
    print("\n============================= Attachment Check =============================")
    print(process_eml_file(file_name, api_key))
    
if __name__ == "__main__":
    main()
"""
Copyright by tr0n9_t4m
"""