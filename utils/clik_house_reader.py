
import clickhouse_connect 
import ast
import logging
from utils.ipmeta.classes import IpMeta
from utils.ipmeta.queries import clickhouse_fetch_query
from fil.settings import CLIK_HOUSE
from utils.ipmeta.readers import readeraction, readerapp, readerdetection, readerdns, readerdomain, readerport, readersite
from multiprocessing import Pool
from functools import partial

logger = logging.getLogger("ip_classification")

def get_clickhouse():
    clickhouse_host = CLIK_HOUSE['HOST']
    clickhouse_port = CLIK_HOUSE['PORT']  
    clickhouse_username = CLIK_HOUSE['USER_NAME']
    clickhouse_password = CLIK_HOUSE['PASSWORD']

    client = clickhouse_connect.get_client(
        host=clickhouse_host,
        port=clickhouse_port,
        user=clickhouse_username,
        password=clickhouse_password
    )
    logger.info(f'connected, ClickHouse Play current version and timezone: {client.server_version} ({client.server_tz})')

    return client
    
def create_ipmeta(result, column_names):
    
    try:
        dict = {}
        for index, data in enumerate(result):
            dict[column_names[index]] = data 
        domain_dist = ast.literal_eval(dict['domain_dist']) if dict['domain_dist'] not in ('',None)  else []
        port_dist   = ast.literal_eval(dict['port_dist']) if dict['port_dist'] not in ('',None)  else []
        appid_dist  = ast.literal_eval(dict['appid_dist']) if dict['appid_dist'] not in ('',None)  else []
        action_dist = ast.literal_eval(dict['action_dist']) if dict['action_dist'] not in ('',None)  else []
        site_dist   = ast.literal_eval(dict['site_dist']) if dict['site_dist'] not in ('',None)  else []
        detection_dist = ast.literal_eval(dict['detection_dist'])  if dict['detection_dist'] not in ('',None)  else []
        dns_dist    = ast.literal_eval(dict['dns_dist']) if dict['dns_dist'] not in ('',None)  else []
        
        for dic in domain_dist+ port_dist+ appid_dist+ action_dist+ site_dist+ detection_dist+ dns_dist:
            dic['ip'] = dict['ip']

        ipmeta = IpMeta(
                    ip = dict['ip'] , time=dict['time'], 
                    asn='no asn' if ('asn' not in dict.keys() or dict['asn'] is None) else dict['asn'],
                    traffic=dict['total_traffics'],
                    bsc=dict['total_bsc'],
                    bcs=dict['total_bcs'],
                    hit=dict['total_hits'],
                    country='no country' if ('country' not in dict.keys() or dict['country'] is None) else dict['country'],
                )
        readerport([ipmeta],port_dist)
        readerdomain([ipmeta],domain_dist)
        readerdns([ipmeta], dns_dist)
        readersite([ipmeta], site_dist)
        readeraction([ipmeta], action_dist)
        readerdetection([ipmeta], detection_dist)
        readerapp([ipmeta], appid_dist)
        return ipmeta
    except Exception as e :
        pass
        # logger.error(f"while creating ipmeta {e}")   


def fetch_clickhouse_ipdata(gte,lt,ips=[],timeframe='hourly'):   
    query  = clickhouse_fetch_query(gte,lt,ips,timeframe=timeframe)
    client = get_clickhouse()
    schema_result = client.query(query)
    column_names  = schema_result.column_names
    results = schema_result.result_set
    logger.info(f'{len(results)} rows fetched.')

    if ips=='only-ip':
        return [IpMeta(ip=row[0]) for row in results]
    
    return create_ipmeta(results, column_names)

def fetch_clickhouse_ipdata_multiprocess(gte,lt,ips=[],timeframe='hourly', processor_number=10):   
    query  = clickhouse_fetch_query(gte,lt,ips,timeframe=timeframe)
    client = get_clickhouse()
    schema_result = client.query(query)
    column_names  = schema_result.column_names
    results = schema_result.result_set
    logger.info(f'{len(results)} {timeframe} rows fetched.')

    partial_create_ipmeta = partial(create_ipmeta, column_names=column_names)
    with Pool(processor_number) as p:
        res = p.map(func=partial_create_ipmeta, iterable=results, chunksize=100000)
    if len(res) > 0:
        out = [result for result in res  if result is not None]
        return out
    return []    
