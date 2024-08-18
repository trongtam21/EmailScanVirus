import requests
def check_ip(ip_address, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API request failed with status code {response.status_code}")
    response_json = response.json()
    if 'data' not in response_json:
        raise ValueError("Invalid response structure")
    attributes = response_json['data']['attributes']
    
    as_owner = attributes.get('as_owner')
    country = attributes.get('country')
    stat_analysis = attributes.get('last_analysis_stats')
    
    malicious = stat_analysis.get('malicious')
    suspicious = stat_analysis.get('suspicious')
    undetected = stat_analysis.get('undetected')
    harmless = stat_analysis.get('harmless')
    
    total = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

    return {
        'IP Address': ip_address,
        'Country': country,
        'Owner': as_owner,
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Undetected': undetected,
        'Total': total
    }
