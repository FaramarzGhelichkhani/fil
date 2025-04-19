import json
import sys

import requests

sys.path.insert(0, './api')
from header import get_proxies, get_root_url

proxies = get_proxies('LCT')
url = get_root_url('LCT', True)

url += 'get/api/'

# Put your desired file address in following variable.
local_file = 'api/local_files/filename.obj'

# Put your query IPs in 'ip_list' value list; as some exist ... .
# ... and put as 'days_ago' the date offset to retrieve date ...
# 0 means today, 1 means yesterday and so on.
data = {
    'ip_list': ['8.8.8.8'],
    'days_ago': 1,
}
r = requests.post(url=url, json=json.dumps(data), proxies=proxies, verify=False)
with open(local_file, 'wb') as f:
    f.write(r.content)
print('File saved successfully.')
