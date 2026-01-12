import requests
import re

def check_domain_vt(target, api_key):
    headers = {"x-apikey": api_key}

    # Simple IP detection
    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)

    if is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code}
