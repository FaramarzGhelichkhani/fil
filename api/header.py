def get_root_url(server='LCT', is_hourly=False):
    """
    Parameters
    ----------
    server : 'LCT' or 'TEST' or 'LOCAL'
    is_hourly : boolean

    Returns
    -------
    url
    """
    if server == 'LCT':
        if is_hourly:
            domain = "172.18.5.77"
        else:
            domain = "172.18.5.39"
    elif server == 'TEST':
        if is_hourly:
            domain = "172.30.113.232"
        else:
            domain = "172.30.113.242"
    elif server == 'LOCAL':
        domain = '127.0.0.1:8000'
    else:
        print("Wrong server")
        exit(0)

    if server == 'LOCAL':
        url = f'http://{domain}/fil/'
    else:
        url = f'https://{domain}/fil/'
    return url


def get_proxies(server='LCT'):
    if server == 'LCT':
        proxies = {
            'http': 'http://yahya:Yaf1401Sor%40t@172.30.222.40:5148',
            'https': 'http://yahya:Yaf1401Sor%40t@172.30.222.40:5148',
        }
    else:
        proxies = {}
    return proxies
