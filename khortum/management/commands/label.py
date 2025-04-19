import shutil
import json
import logging
import os
import pickle
from pathlib import Path
from utils.utils import get_last_day
import psycopg2
from django.core.management.base import BaseCommand

import os
import pickle

from datasets import Dataset
from datasets.info import DatasetInfo

from fil.settings import PESTE_HOST, PESTE_NAME, PESTE_PASSWORD, PESTE_USER, REDIS_IP_DAILY_DB, DATASET_RAW_FILES, \
    DATASET_ADDRESS, DB_HOST, DB_NAME, DB_PASSWORD, DB_USER, VERSION, PRODUCTION_SERVER
from khortum.models import Payload
from utils.ipmeta.classes import *
from utils.file_handler import load_objects_from_redis, get_keys_from_redis
from hafeze.utils.labeling import label

DIR = Path(__file__).resolve().parent.parent.parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)
logger = logging.getLogger("ip_classification.main")

def read_file(directory):
    result = []
    for filename in os.listdir(directory):
        if filename.endswith(".csv"):
            path = os.path.join(directory, filename)
            with open(path, 'rb') as file:
                while True:
                    try:
                        data = pickle.dumps(pickle.load(file))
                        result.append(data)
                    except EOFError:
                        # reached the end of the file
                        break
    return result


def fetch_ip_app_id_from_peste(query):
    peste = psycopg2.connect(host=PESTE_HOST, database=PESTE_NAME, user=PESTE_USER, password=PESTE_PASSWORD)
    peste_cursor = peste.cursor()
    peste_cursor.execute(query)
    result = peste_cursor.fetchall()
    ip_dict = {}
    for row in result:
        ip, app_id = row[0:2]
        if app_id not in ip_dict.keys():
            ip_dict[app_id] = set()
        ip_dict[app_id].add(ip)
    return ip_dict


def fetch_input_ipmeta_from_fil(offset_days='1 d', db_host=PRODUCTION_SERVER, db_name='fildb_production', save=True):
    logger.info(f"getting fil input ips", {"command": "label"})
    from psycopg2 import extras

    query = f"""
                    with ips as (
                    select distinct ip, payload , p.name  
                    from khortum_ip 
                    join khortum_payload p on payload_id = p.id and payload < 1000*1000 
                    join  khortum_source s  on source_id = s.id and (s.name = 'input' or s.name = 'spider') 
                    where insert_time > now() - interval '{offset_days}' and  \"check\" != 'blocked' 
                    )

                    select distinct on (ipmeta.ip , time)
                    time,ipmeta.ip , payload , name as payload_name  , totalbsc as bsc , totalbcs as bcs, totalhit as hit, total_traffic as traffic, totalpercent as percent , country, asn 
                    , domain_dist, port_dist, dns_dist, appid_dist as appiddist, size_dist, detection_dist
                    from ipmeta
                    join ips on ips.ip = ipmeta.ip
                    where time >now() -  interval '{offset_days}'
                    """

    host = DB_HOST if db_host is None else db_host
    db   = DB_NAME if db_name is None else db_name
    database = psycopg2.connect(host=host, database=db, user=DB_USER, password=DB_PASSWORD)
    database_cursor = database.cursor(cursor_factory=extras.DictCursor)
    database_cursor.execute(query)
    rows = database_cursor.fetchall()
    database_cursor.close()
    database_cursor.close()

    ipmetas = []
    for row in rows:
        row = dict(row)

        payload = row.pop('payload')
        payload_name = row.pop('payload_name')
        row['domain_dist'] = [DomainDist(**dist) for dist in row['domain_dist']]
        row['port_dist'] = [PortDist(**dist) for dist in row['port_dist']]
        row['dns_dist'] = [DnsDist(**dist) for dist in row['dns_dist']]
        row['appiddist'] = [AppDist(**dist) for dist in row['appiddist']]
        row['size_dist'] = [SizeDist(**dist) for dist in row['size_dist']]
        row['detection_dist']  = [DetectionDist(**dist)   for dist    in row['detection_dist']]
        ipmeta = IpMeta(**row)
        ipmeta.payload = payload
        ipmeta.label =   payload
        ipmeta.payload_name = payload_name
        ipmeta.source = 'fil-input'

        ipmetas.append(ipmeta)

    if save:
        with open(f'{DATASET_RAW_FILES}Fil-input-Ipmeta-entire.csv', 'wb') as csvfile:
            for ipmeta in ipmetas:
                pickle.dump([ipmeta, ipmeta.payload], csvfile)
        return len(ipmetas)
    else:
        return ipmetas 

def get_payload_app_name(payload):
    try:
        return Payload.objects.get(payload=payload).name
    except:
        return 'Other'


def save_jamal_ips(date_offset_gt, date_offset_lt, offset):
    logger.info(f"getting input ips", {"command": "label"})
    query = f"""
                with log as(
                    select distinct ip , payload as app_id
                    from tasfie_pesteip 
                    where lower(source) in ('jamal')
                        and insert_time > now() - interval '{date_offset_gt}' and insert_time < now() - interval '{date_offset_lt}'
                        group by ip , app_id
                )
                select ip, app_id
                from log
                where not ip << '127.0.0.0/8'
                    and not ip in (
                        select ip
                        from tasfie_pesteip
                        where insert_time > now() - interval '1 d'
                            and lower(source) in ('jamal')
                        group by ip
                        having count(distinct payload) > 1
                    )
                order by ip
            """
    result = 0
    ip_dict = fetch_ip_app_id_from_peste(query)
    with open(f'{DATASET_RAW_FILES}w-{get_last_day(offset)}.csv', 'wb') as csvfile:
        for payload in ip_dict.keys():
            payload_name = get_payload_app_name(payload)
            for ipmeta_pickled in [obj for obj in list(filter(lambda x: x is not None,
                                                              load_objects_from_redis(keys=ip_dict[payload],
                                                                                      db=REDIS_IP_DAILY_DB)))]:
                ipmeta = pickle.loads(ipmeta_pickled)
                ipmeta.source = 'Jamal'
                ipmeta.payload = payload
                ipmeta.payload_name = payload_name
                pickle.dump([ipmeta, payload], csvfile)
            logger.debug(f"for app_id:{payload} wrote {len(ip_dict[payload])} data",
                         {"command": "label", "ips": len(ip_dict[payload]),
                          "application_name": payload_name})
            result += len(ip_dict[payload])
    return result


def get_input_ips(date_offset_gt, date_offset_lt, offset):
    logger.info(f"getting input ips", {"command": "label"})
    apps = Payload.objects.filter(generating=True)
    appid_to_payload = {app.payload: app for app in apps}
    app_ids = appid_to_payload.keys()
    query = f"""
                with log as(
                    select distinct ip , app_id
                    from tasfie_pestetip 
                    where app_id in ({[id.__str__() for id in app_ids].__str__()[1:-1]})
                        and update_time > now() - interval '{date_offset_gt}' and update_time < now() - interval '{date_offset_lt}'
                        and lower(source) in ('spider')
                        group by ip , app_id
                        having not array['fil'] <@ array_agg(distinct source::text)
                )
                select ip, app_id
                from log
                where not ip << '127.0.0.0/8'
                    and not ip in (
                        select ip
                        from tasfie_pestetip
                        where update_time > now() - interval '30 d'
                            and lower(source) in ('spider')
                        group by ip
                        having count(distinct app_id) > 1
                    )
                order by ip
            """
    ip_dict = fetch_ip_app_id_from_peste(query)
    result = 0
    with open(f'{DATASET_RAW_FILES}b-{get_last_day(offset)}.csv', 'wb') as csvfile:
        for payload in ip_dict.keys():
            payload_name = get_payload_app_name(payload)
            for ipmeta_pickled in [obj for obj in
                                   list(filter(lambda x: x is not None and pickle.loads(x).total_traffic > 1000 ** 3,
                                               load_objects_from_redis(keys=ip_dict[payload], db=REDIS_IP_DAILY_DB)))]:
                ipmeta = pickle.loads(ipmeta_pickled)
                ipmeta.source = 'spider'
                ipmeta.payload = payload
                ipmeta.payload_name = payload_name
                pickle.dump([ipmeta, payload], csvfile)
            logger.debug(f"for app_id:{payload} wrote {len(ip_dict[payload])} data",
                         {"command": "label", "ips": len(ip_dict[payload]),
                          "application_name": payload_name})
            result += len(ip_dict[payload])
    return result


def get_labeled_ipmetas(offset):
    """ function to fetch and save ipmetas for 27459 and 28392, daily basis. """

    logger.info(f"getting Iran and Freeze ips", {"command": "label"})
    keys = get_keys_from_redis(REDIS_IP_DAILY_DB)
    ips = [str(ip, 'utf-8') for ip in keys]
    print("len ips: ", len(ips))
    Iran, freeze = label(ips)

    iran_result = 0
    with open(f'{DATASET_RAW_FILES}Iran-{get_last_day(offset)}.csv', 'wb') as csvfile:
        ipmeta_pickled_Iran = load_objects_from_redis(keys=Iran, db=REDIS_IP_DAILY_DB)
        for ipmeta_pickled in ipmeta_pickled_Iran:
            ipmeta = pickle.loads(ipmeta_pickled)
            ipmeta.payload = 27459
            ipmeta.payload_name = 'Iran Internal'
            ipmeta.source = 'peste'

            pickle.dump([ipmeta, 27459], csvfile)
            iran_result += 1
    logger.debug(f"for app_id:{27459} wrote {iran_result} data",
                 {"command": "label", "ips": iran_result, "application_name": 'Iran Internal'})
    freeze_result = 0
    with open(f'{DATASET_RAW_FILES}Freeze-{get_last_day(offset)}.csv', 'wb') as csvfile:
        ipmeta_pickled_freez = load_objects_from_redis(keys=freeze, db=REDIS_IP_DAILY_DB)
        for ipmeta_pickled in ipmeta_pickled_freez:
            ipmeta = pickle.loads(ipmeta_pickled)
            ipmeta.payload = 28392
            ipmeta.payload_name = 'Freeze Universal'
            ipmeta.source = 'peste'

            pickle.dump([ipmeta, 28392], csvfile)
            freeze_result += 1
    logger.debug(f"for app_id:{28392} wrote {freeze_result} data.",
                 {"command": "label", "ips": freeze_result, "application_name": 'Freeze Universal'})

    return iran_result + freeze_result


def build_dataset():
    shutil.rmtree(DATASET_ADDRESS)
    labeled_ipmetas = read_file(DATASET_RAW_FILES)
    dataset = Dataset.from_list([{'labeled_data': x} for x in labeled_ipmetas],
                                info=DatasetInfo(
                                    **{"description": f"created date is {get_last_day(0)}", 'version': VERSION}))
    dataset.save_to_disk(DATASET_ADDRESS)
    logger.info(f"Dataset created.")


class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('day_number', nargs='+', type=int)

    def handle(self, *args, **options):
        offset_day = options['day_number'][0]
        logger.info(f"start labeling for {offset_day} days offset.", {"command": "label"})

        offset_insert = 0
        date_offset_lt = str(0) + ' d'
        date_offset_gt = str(offset_day) + ' d'
        num = 0
        num += save_jamal_ips(date_offset_gt, date_offset_lt, offset_insert)
        num += get_input_ips(date_offset_gt, date_offset_lt, offset_insert)
        num += get_labeled_ipmetas(offset_insert)
        num += fetch_input_ipmeta_from_fil()
        logger.info(f"{num} labeled.", {"command": "label"})
        build_dataset()
