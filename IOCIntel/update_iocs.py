import os
import requests
from datetime import datetime, timezone

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
STATE_FILE = ".state/otx_last_success.txt"

def read_last_success():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, 'r') as f:
        ts = f.read().strip()
        return ts if ts else None

def write_last_success(timestamp):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        f.write(timestamp)

def get_pulses_updated_since(api_key, since):
    headers = {'X-OTX-API-KEY': api_key}
    params = {'modified_since': since} if since else {}
    pulses = []
    page = 1

    while True:
        params['page'] = page
        resp = requests.get(API_URL, headers=headers, params=params)
        if resp.status_code == 403:
            print(f"ERROR response {resp.status_code} {resp.json()}")
            exit(4)
        resp.raise_for_status()
        data = resp.json()

        pulses.extend(data.get('results', []))
        if not data.get('next'):
            break
        page += 1

    return pulses

def save_iocs(iocs, filename):
    os.makedirs('IOCIntel', exist_ok=True)
    filepath = os.path.join('IOCIntel', filename)
    existing = set()
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            existing = set(line.strip() for line in f if line.strip())
    updated = set(iocs) - existing
    if updated:
        with open(filepath, 'a') as f:
            for item in sorted(updated):
                f.write(item + "\\n")
    return len(updated)

def extract_iocs(pulses):
    ips = set()
    domains = set()
    hashes = set()

    for pulse in pulses:
        for indicator in pulse.get('indicators', []):
            itype = indicator.get('type')
            val = indicator.get('indicator')
            if itype == 'IPv4':
                ips.add(val)
            elif itype == 'domain':
                domains.add(val)
            elif itype in ('FileHash-MD5', 'FileHash-SHA256', 'FileHash-SHA1'):
                hashes.add(val)
    return ips, domains, hashes

def main():
    api_key = os.getenv('OTX_API_KEY')
    if not api_key:
        print("ERROR: OTX_API_KEY environment variable not set")
        exit(1)

    last_success = read_last_success()
    print(f"[+] Last run timestamp: {last_success if last_success else 'None'}")

    pulses = get_pulses_updated_since(api_key, last_success)
    print(f"[+] Fetched {len(pulses)} pulses.")

    ips, domains, hashes = extract_iocs(pulses)

    n_ip = save_iocs(ips, 'ip_addresses.txt')
    n_domain = save_iocs(domains, 'domains.txt')
    n_hash = save_iocs(hashes, 'hashes.txt')

    print(f"[+] Total new IPs: {n_ip}")
    print(f"[+] Total new Domains: {n_domain}")
    print(f"[+] Total new Hashes: {n_hash}")

    now_iso = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    write_last_success(now_iso)
    print(f"[+] Updated last success timestamp to: {now_iso}")

if __name__ == "__main__":
    main()
