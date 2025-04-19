import psycopg2
from netaddr import IPSet, IPAddress, IPNetwork
import logging
from fil.settings import PESTE_HOST, PESTE_NAME, PESTE_USER, PESTE_PASSWORD, LABEL_CORE_NUMBER

peste = psycopg2.connect(host=PESTE_HOST, database=PESTE_NAME, user=PESTE_USER, password=PESTE_PASSWORD)
logger = logging.getLogger("ip_classification.main")


def fetch_white_ip():
    iran = get_iran_ranges()
    freeze = get_freeze_ranges()
    white = iran + freeze
    ip_set = IPSet(white)
    print("number of white range: ", len(white))
    return ip_set


def get_iran_ranges():
    query_text = """
    select * from (select distinct ip from tasfie_pesteip where payload = 27459)q order by random() limit 50
    """

    query = peste.cursor()
    query.execute(query_text)

    result = query.fetchall()
    ip_list = [IPNetwork(data[0]) for data in result]
    return ip_list


def get_freeze_ranges():
    query_text = """
    select * from (select distinct ip from tasfie_pesteip where payload = 28392)q order by random() limit 5000
    """

    query = peste.cursor()
    query.execute(query_text)

    result = query.fetchall()
    ip_list = [IPNetwork(data[0]) for data in result]
    return ip_list


def custom_tasfie_white(payload_list, day):
    query_text = f"""
    select distinct ip , 'white' as label from tasfie_pesteip where 
    insert_time > now() -  interval'{day} day' and
    payload  in ({payload_list.__str__()[1:-1]})
    GROUP BY 1 
    HAVING COUNT(DISTINCT PAYLOAD) = 1
    """
    query = peste.cursor()
    query.execute(query_text)
    result = query.fetchall()
    ip_payload = result
    return ip_payload


def get_vpn_ip_payload(payload_list=[], day=30):
    vpn_payload = {27523: 'lantern', 27525: 'pspiphon', 27941: 'psiphon_fastly', 27737: 'pspiphon_akamai',
                   27321: 'xvpn', 27652: 'Ultrasurf'
        , 28047: 'KUTO VPN', 28241: 'Star VPN', 28199: 'MiniFox VPN'}

    payload_list_default = list(vpn_payload.keys())
    payload_list = payload_list_default if len(payload_list) == 0 else payload_list

    query_text = f"""
    select distinct ip , (ARRAY_AGG(DISTINCT payload))[1] from tasfie_pesteip where 
    insert_time > now() -  interval'{day} day' and
    payload  in ({payload_list.__str__()[1:-1]}) 
    and source <> 'fil' 
    GROUP BY 1 
    HAVING COUNT(DISTINCT PAYLOAD) = 1

    union

    select distinct ip , (ARRAY_AGG(DISTINCT app_id))[1] from tasfie_pestetip where 
    insert_time > now() -  interval'{day} day' and
    app_id  in ({payload_list.__str__()[1:-1]})
    and source <> 'fil'
    GROUP BY 1 
    HAVING COUNT(DISTINCT app_id) = 1

    """
    query = peste.cursor()
    query.execute(query_text)
    result = query.fetchall()
    ip_payload = result
    print("number of vpn ip: ", len(ip_payload))
    return ip_payload


def fetch_all_labels(payload_list=[], day=30):
    white_ip_set = fetch_white_ip()
    vpn_labels_dict = {data[0]: data[1] for data in get_vpn_ip_payload(payload_list, day)}

    return {'white': white_ip_set, 'vpn': vpn_labels_dict}



def initialize_worker(iran, freeze):
    global Iran, Freeze
    Iran = iran
    Freeze = freeze

def check_ip(ips, results):
    logger.debug(f"checking ip started")
    ip_results = []
    for single_ip in ips:
        if IPAddress(single_ip) in Iran:
            ip_results.append((single_ip, 'Iran'))
        elif IPAddress(single_ip) in Freeze:
            ip_results.append((single_ip, 'Freeze'))

    results.extend(ip_results)

def label(ips):
    i_o = []
    f_o = []
    Iran = IPSet(get_iran_ranges())
    Freeze = IPSet(get_freeze_ranges())
    from multiprocessing import Pool, Manager
    with Manager() as manager:
        results = manager.list()
        with Pool(processes=LABEL_CORE_NUMBER, initializer=initialize_worker, initargs=(Iran, Freeze)) as pool:
            pool.starmap(check_ip, [(ips, results)], chunksize=100000)

        for ip, location in results:
            if location == 'Iran':
                i_o.append(ip)
            elif location == 'Freeze':
                f_o.append(ip)

    return i_o, f_o
