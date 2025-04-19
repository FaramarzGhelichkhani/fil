import json
import logging
import os
import psycopg2
from pathlib import Path
from psycopg2 import extras
from utils.ipmeta.classes import AppDist, DnsDist, DomainDist, IpMeta, PortDist, SizeDist, DetectionDist
from fil.settings import DB_HOST, DB_NAME, DB_USER, DB_PASSWORD

logger = logging.getLogger("ip_classification.main")
DIR = Path(__file__).resolve().parent.parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)

logger = logging.getLogger("ip_classification")

DIR = Path(__file__).resolve().parent.parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)

def fetch_input_ipmeta_from_fil(payload,offset_days=1, db_host = None , db_name=None, offset_hours=None ):
    
    interval = f"{offset_days} d" if offset_hours is None else f"{offset_hours} h"
    query = f"""
   with ips as (select distinct ip, payload , p.name  
                    from khortum_ip 
                    join khortum_payload p on payload_id = p.id and payload < 1000*1000 
                    join  khortum_source s  on source_id = s.id and s.name in ('input','spider')
                    where insert_time  >=  date_trunc('day',now()::timestamp - interval'{interval}') and p.payload = {payload}  and  \"check\" != 'blocked')

                    select distinct on (ipmeta.ip , time)
                    time,ipmeta.ip , payload , name as payload_name  , totalbsc as bsc , totalbcs as bcs, totalhit as hit, total_traffic as traffic, totalpercent as percent , country, asn 
                    , domain_dist, port_dist, dns_dist, appid_dist as appiddist, size_dist, detection_dist
                    from ipmeta
                    join ips on ips.ip = ipmeta.ip
                    where insert_time  >=  date_trunc('day',now()::timestamp - interval'{interval}')
                    order by time desc 
                    """
    host_db = DB_HOST if db_host is None else db_host
    dbname  = DB_NAME if db_name is None else db_name
    database = psycopg2.connect(host=host_db, database=dbname, user=DB_USER, password=DB_PASSWORD)
    database_cursor = database.cursor(cursor_factory=extras.DictCursor)
    database_cursor.execute(query)
    rows = database_cursor.fetchall()
    database_cursor.close()
    database_cursor.close()

    ipmetas =[]
    for row in rows:
        row = dict(row)
        
        payload = row.pop('payload')
        payload_name = row.pop('payload_name')
        row['domain_dist']     = [DomainDist(**dist)   for dist    in row['domain_dist']]
        row['port_dist']       = [PortDist(**dist)   for dist    in row['port_dist']]
        row['dns_dist']        = [DnsDist(**dist)  for dist    in row['dns_dist']]
        row['appiddist']       = [AppDist(**dist)   for dist    in row['appiddist']]
        row['size_dist']       = [SizeDist(**dist)   for dist    in row['size_dist']]
        row['detection_dist']  = [DetectionDist(**dist)   for dist    in row['detection_dist']]
        ipmeta = IpMeta(**row)
        ipmeta.payload = payload
        ipmeta.label = payload
        ipmeta.payload_name =  payload_name
        ipmeta.source = 'fil-input_spider'

        ipmetas.append(ipmeta)
    return ipmetas


def fetch_ipmeta_from_fil(ips,db_host = None,ip_type='ip_obj'):
    query = f""" select distinct on (ipmeta.ip , time)
                    time,ipmeta.ip , totalbsc as bsc , totalbcs as bcs, totalhit as hit, total_traffic as traffic, totalpercent as percent , country, asn 
                    , domain_dist, port_dist, dns_dist, appid_dist as appiddist, size_dist, detection_dist
                    from ipmeta
                    where 
                    """
    conditions = []
    
    for ip in ips:
        if ip_type == 'ip_obj':
            condition = f"(ip = '{ip.ip}' and date_trunc('day',insert_time) = date_trunc('day','{ip.insert_time}'::timestamp) )"
        elif ip_type == 'str':
            condition = f"(ip = '{ip}' )"
        else:
            raise ValueError("set right type_ip :( .")    
        
        conditions.append(condition)
    query += " OR ".join(conditions)
    query += " order by time desc "    
    host_db = DB_HOST if db_host is None else db_host
    database = psycopg2.connect(host=host_db, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    database_cursor = database.cursor(cursor_factory=extras.DictCursor)
    database_cursor.execute(query)
    rows = database_cursor.fetchall()
    database_cursor.close()
    database_cursor.close()

    ipmetas =[]
    for row in rows:
        row = dict(row)
                
        row['domain_dist']     = [DomainDist(**dist)   for dist    in row['domain_dist']]
        row['port_dist']       = [PortDist(**dist)   for dist    in row['port_dist']]
        row['dns_dist']        = [DnsDist(**dist)  for dist    in row['dns_dist']]
        row['appiddist']       = [AppDist(**dist)   for dist    in row['appiddist']]
        row['size_dist']       = [SizeDist(**dist)   for dist    in row['size_dist']]
        row['detection_dist']  = [DetectionDist(**dist)   for dist    in row['detection_dist']]

        ipmeta = IpMeta(**row)


        ipmetas.append(ipmeta)

    return ipmetas    


def fetch_last_ipmeta_from_ip(ips=[]):
    all_ipmetas = fetch_ipmeta_from_fil(ips)
    dict_ipmeta = {}
    for ipmeta in all_ipmetas:
        if dict_ipmeta.get(ipmeta.ip) is None:
            dict_ipmeta[ipmeta.ip] = ipmeta