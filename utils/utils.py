import logging
import requests
import datetime
import psycopg2
from fil.settings import AIRFLOW_HOST, IS_HOURLY, PESTE_HOST, PESTE_NAME, PESTE_PASSWORD, PESTE_USER
from fil.settings import SMS_LOG_ADDRESS
from utils.ipmeta.classes import IpMeta
from utils.ipmeta.readers import readeraction, readerapp, readerdetection, readerdns, readerdomain, readerport, readersite

logger = logging.getLogger("ip_classification.main")


def  get_last_day(d: int,timeframe: str='hourly'):
    if timeframe.lower() == 'hourly':
        now = (datetime.datetime.fromtimestamp(datetime.datetime.timestamp(datetime.datetime.now() - datetime.timedelta(hours=d))))
        return now.strftime("%Y-%m-%d %H:00:00")
    elif timeframe.lower() == 'daily':
        now = (datetime.datetime.fromtimestamp(datetime.datetime.timestamp(datetime.datetime.now() - datetime.timedelta(days=d))))
        return now.strftime("%Y-%m-%d")
    elif timeframe in ('5min', 'Minutly'):
        now = datetime.datetime.now()
        rounded_now = now - datetime.timedelta(minutes=now.minute % 5)
        now = (datetime.datetime.fromtimestamp(datetime.datetime.timestamp( rounded_now - datetime.timedelta(minutes=d*5))))
        return now.strftime("%Y-%m-%d %H:%M:00")    


def todict(obj):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict(v)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        return data
    else:
        return obj


def todict_digest(obj):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict_digest(v)
        return data
    elif hasattr(obj, "_ast"):
        return todict_digest(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        l = [todict_digest(v) for v in obj[0:min(3, len(obj))]]
        if len(obj) > 3:
            l.extend([f' ... and {len(obj) - 3} more!'])
        return l
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict_digest(value))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        return data
    else:
        return obj


def save_sms_data(command, message):
    f = open(SMS_LOG_ADDRESS, "a")
    f.write(f"{message}\n")
    f.close()


def initialize_sms_data():
    f = open(SMS_LOG_ADDRESS, "w")
    s = datetime.datetime.now().strftime("%Y/%m/%d")
    f.write(f"{s}\n")
    if IS_HOURLY:
        remember_stats = get_dag_run_stats(dag_id='fil_hourly_remember')
        f.write(f"Remember suceess: {remember_stats['success']}, failed: {remember_stats['failed']} \n")
    f.close()

def get_dag_run_stats(dag_id):
    start_date = datetime.datetime.now().strftime("%Y-%m-%d") + 'T00%3A00%3A00%2B00%3A00'
    airflow_host = 'http://' + AIRFLOW_HOST
    url = f'/api/v1/dags/{dag_id}/dagRuns?execution_date_gte={start_date}'
    session = requests.Session()
    session.auth =('airflow','da123456airflow')
    auth = session.post(airflow_host)
    headers = {'Content-type': 'application/json'}
    dag_stats = session.get(url=airflow_host+url,headers=headers)
    remember_stats = {'success': 0 , 'failed':0, 'running':0}
    if dag_stats.status_code == 200:
        airflowdata = dag_stats.json()
        for dict in airflowdata['dag_runs']:
            remember_stats[dict['state']] +=1
    return remember_stats        

def dicttoIpMeta(dicts):
    ipmetalist =[]

    for dict in dicts:
        domain_dist =dict['domain_dist'] if dict['domain_dist'] not in ('',None)  else []
        port_dist   =dict['port_dist'] if dict['port_dist'] not in ('',None)  else []
        appid_dist  =dict['appid_dist'] if dict['appid_dist'] not in ('',None)  else []
        action_dist =dict['action_dist'] if dict['action_dist'] not in ('',None)  else []
        site_dist   =dict['site_dist'] if dict['site_dist'] not in ('',None)  else []
        detection_dist =dict['detection_dist']  if dict['detection_dist'] not in ('',None)  else []
        dns_dist    =dict['dns_dist'] if dict['dns_dist'] not in ('',None)  else []
        
        for dic in domain_dist+ port_dist+ appid_dist+ action_dist+ site_dist+ detection_dist+ dns_dist:
            dic['ip'] = dict['ip']

        ipmeta = IpMeta(
                    ip = dict['ip'] , time=dict['time'], 
                    asn='no asn' if ('asn' not in dict.keys() or dict['asn'] is None) else dict['asn'],
                    traffic=dict['total_traffic'],
                    bsc=dict['totalbsc'],
                    bcs=dict['totalbcs'],
                    hit=dict['totalhit'],
                    country='no country' if ('country' not in dict.keys() or dict['country'] is None) else dict['country'],
                )
        readerport([ipmeta],port_dist)
        readerdomain([ipmeta],domain_dist)
        readerdns([ipmeta], dns_dist)
        readersite([ipmeta], site_dist)
        readeraction([ipmeta], action_dist)
        readerdetection([ipmeta], detection_dist)
        readerapp([ipmeta], appid_dist)
        ipmetalist.append(ipmeta)

    return  ipmetalist

def send_output_to_peste(data,source,main=False):
        """
        insert data into peste
        data is lis of IP objects.
        main True mean pestip for db
        main Fals mean pestetip for db
        """
        database = psycopg2.connect(host=PESTE_HOST, database=PESTE_NAME, user=PESTE_USER, password=PESTE_PASSWORD )
        database_cursor = database.cursor()
        queries = {"temp":f"""insert into tasfie_pestetip(ip, app_id, insert_time, update_time, source, comment) values (%s,%s,%s,%s,%s,%s);""",
                "main":   f"""insert into tasfie_pesteip(ip, service, payload, insert_time, update_time, source, comment) values 
                    (%s,0,%s,%s,%s,%s,%s) ON CONFLICT (ip, service, payload, source) DO UPDATE SET update_time = now();
                """        
        }
        query = queries["main"] if main else queries["temp"]
        counter = 0 
        for output_ip in data:
            if output_ip.check == 'approved':
                t = (output_ip.ip, output_ip.payload.payload, datetime.datetime.now(), datetime.datetime.now(), 'fil_' + source , output_ip.type)
                database_cursor.execute(database_cursor.mogrify(query, t))
                counter +=1
            else:
                continue
        logger.info(f"{counter} ips inserted into peste.")    
        database.commit()
