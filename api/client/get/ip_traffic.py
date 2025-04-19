import json
import sys, os
import requests
import time

sys.path.insert(0, './api')
from header import get_proxies, get_root_url

proxies = get_proxies('LCT')
url = get_root_url('LCT', True)
url += 'get/ip_traffic/'
data = {'ips': [
    '1.1.1.1', '8.8.8.8'
]}
sys.stderr = open(os.devnull, 'w')
start_time = time.time()
r = requests.post(url=url, json=json.dumps(data), proxies=proxies, verify=False)
end_time = time.time()
elapsed_time = end_time - start_time
sys.stderr = sys.stdout
print(f"status_code: {r.status_code} ({'{:.3f} seconds'.format(elapsed_time)})")
print(r.content)
response = json.loads(r.content)
print(json.dumps(response, indent=4))
print(f"{response['total_traffic']}")
