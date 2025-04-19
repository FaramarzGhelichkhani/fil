import json
import sys

import requests

sys.path.insert(0, './api')
from header import get_proxies, get_root_url

proxies = get_proxies('LCT')
url = get_root_url('LCT', True)

url += 'script/get_domain_ips/'
domain = 'google.com'
r = requests.get(url=url+domain, proxies=proxies, verify=False)
print(r.content)
