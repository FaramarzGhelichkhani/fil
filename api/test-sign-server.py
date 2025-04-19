import json

import requests

from header import get_root_url, get_proxies

proxies = get_proxies('LCT')
url = get_root_url('LCT', False)
url += 'script/'

# Put your signature script in this variable
script = """
def Azadrah22(database_ipmeta, input_ipmeta):
    sum_port = 0
    for port_dist in database_ipmeta.port_dist:
        if port_dist.port == 80:
            sum_port = sum_port + port_dist.percent
    if sum_port < 0.9:
        return False
    return True
positive = Azadrah22(database_item, input_item)
"""

inp_ips = ['8.8.8.8']
unlabeled_ips = []
# change username to your username
# fill input_ips with list of labeled ips
# payload is your app payload
# if date offset is 2 means your unlabeled ips load from 3 days ago
# unlabeled_limit is the number of unlabeled ips you want to check
# if you whant to test a signature in DB comment the script line
# input_ips can be empty then use khortum ips
# unlabeled_ips can be empty then use remember ips
data = {
    'signature': {
        'name': "Test Sign Api",
        'script': script,
    },
    'payload': 27321,
    'username': 'sadeghian.a',
    'unlabeled_ips': unlabeled_ips,
    'input_ips': inp_ips,
    'date_offset': 1,
    'unlabeled_limit': 1000,
}

r = requests.get(url=url, json=json.dumps(data), proxies=proxies, verify=False)
print(json.dumps(json.loads(r.content), indent=4))
