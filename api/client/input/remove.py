import json
import sys

import requests

sys.path.insert(0, './api')
from header import get_proxies, get_root_url

proxies = get_proxies('LCT')
url = get_root_url('LCT', True)

url += 'input/remove/'

# Put your desired file address in following variable.
local_file = 'api/local_files/filename.obj'

data = {
    'name': "test-ipmeta",
    'payload': 27227,

}
r = requests.post(url=url, json=json.dumps(data), proxies=proxies, verify=False)
print(r.status_code, r.content)