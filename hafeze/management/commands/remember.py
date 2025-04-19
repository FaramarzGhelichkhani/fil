import json
import logging
import math
import multiprocessing
import os
import pickle
import threading
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path
from threading import Thread
from typing import List

from utils.clik_house_reader import fetch_clickhouse_ipdata

global_ipmeta_count = 0
thread_lock = threading.Lock()
import urllib3
from django.core.management.base import BaseCommand

from fil.settings import ELASTIC, REDIS_IP_DAILY_DB , REDIS_IP_HOURLY_DB, REDIS_IP_5MIN_DB, REDIS_DNS_DB, REDIS_DOMAIN_DB, REDIS_TMP_DB
from fil.settings import REMEMBER_BATCH_SIZE, REMEMBER_NUMBER_OF_PROCESSOR, REMEMBER_FETCH_SIZE, ATTACK_CORE_NUMBER
from utils.elastic_reader import fetch_elastic
from utils.file_handler import save_ipmetas_in_redis, get_keys_from_redis, load_objects_from_redis, \
    save_domainmetas_in_redis, save_object_in_redis, save_ipmeta_in_redis_multiprocess
from utils.ipmeta.classes import IpMeta, DomainMeta
from utils.ipmeta.main import get_all_server_ips, get_all_resolved_ips, produce_ipmeta_clickhouse
from utils.ipmeta.main import produce_ipmeta
from utils.utils import get_last_day, save_sms_data, initialize_sms_data

urllib3.disable_warnings()
DIR = Path(__file__).resolve().parent.parent.parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)

logger = logging.getLogger("ip_classification")
lock = multiprocessing.Lock()


def extract_domain_metas(chunk):
    domain_list = chunk[1]
    dns_list = chunk[2]
    progress = chunk[3]
    totall_count = chunk[4]
    tmp_dns_list = []
    tmp_domain_list = []
    for item in chunk[0]:
        if progress.value % 100 == 0:
            progress.value += 100
            print(f"progress: {100 * progress.value / totall_count}%", end='\r')
        unlabeled_ipmeta = pickle.loads(item)
        tmp_dns_list.extend(get_all_resolved_ips(unlabeled_ipmeta))
        tmp_domain_list.extend(get_all_server_ips(unlabeled_ipmeta))
    with lock:
        dns_list.extend(tmp_dns_list)
        domain_list.extend(tmp_domain_list)


def create_all_domainmetas(ip_db, domain_db):
    logger.debug("start detect", {"command": "detect"})
    keys = get_keys_from_redis(ip_db)
    all_unlabeled_ipmetas = load_objects_from_redis(keys, ip_db)
    # sms message log
    domains = multiprocessing.Manager().list()
    dnss = multiprocessing.Manager().list()
    progress = multiprocessing.Manager().Value('i', 0)
    totall_count = REMEMBER_FETCH_SIZE
    chunks = [(c, domains, dnss, progress, totall_count) for c in
              chunking_data(all_unlabeled_ipmetas, ATTACK_CORE_NUMBER)]
    pool = multiprocessing.Pool(ATTACK_CORE_NUMBER)
    pool.map(func=extract_domain_metas, iterable=chunks)
    pool.close()
    pool.join()
    uniques = set()
    logger.info(f"{len(domains)} domain tuple found.", {"command": "remember"})
    logger.info(f"{len(dnss)} dnss tuple found.", {"command": "remember"})
    for domain in domains:
        uniques.add(domain[0])
    for dns in dnss:
        uniques.add(dns[0])
    logger.info(f"{len(uniques)} unique domains found.", {"command": "remember"})
    domain_metas = {}
    i = 0
    for d in uniques:
        i += 1
        if i % 1000 == 0:
            print(f"{round(100 * i / len(uniques), 2)}% ", end='\r')
        domain_metas[d] = DomainMeta(domain=d, resolved_ips=[], server_ips=[])
    logger.info(f"dictionary initialized.", {"command": "remember"})
    i = 0
    for d in domains:
        i += 1
        if i % 1000 == 0:
            print(f"{round(100 * i / len(uniques), 2)}% ", end='\r')
        domain_metas[d[0]].server_ips.append(d[1])
    logger.info(f"server_ips constructed.", {"command": "remember"})
    i = 0
    for d in dnss:
        i += 1
        if i % 1000 == 0:
            print(f"{round(100 * i / len(uniques), 2)}% ", end='\r')
        domain_metas[d[0]].resolved_ips.append(d[1])
    logger.info(f"resolved_ips constructed.", {"command": "remember"})
    if save_domainmetas_in_redis(list(domain_metas.values()), domain_db, timedelta(days=7)):
        logger.info(f"Saved all domainmetas into Redis.", {"state": "done", "command": "remember"})
    logger.info("done", {"command": "remember"})


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('-o','--offset', default=0, type=int)
        parser.add_argument('-t','--timeframe', default='minutely', type=str)


    def handle(self, *args, **options):
        date_offset = options['offset']
        timeframe = {"daily":"Daily", "hourly":"hourly", "minutely":"Minutly"}
        timeframe = timeframe[options["timeframe"].lower()]

        fetch_all_unlabeld_ipmeta_click_house(date_offset, timeframe=timeframe)
        logger.info("done", {"command": "remember"})



def fetch_all_unlabeld_ipmeta_click_house(date_offset,timeframe='hourly'):
    gte  =  get_last_day(1 + date_offset, timeframe=timeframe)
    lt   =  get_last_day(0 + date_offset, timeframe=timeframe)
    if timeframe != 'Minutly':
        ipMetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,timeframe=timeframe, processor_number=REMEMBER_NUMBER_OF_PROCESSOR)
    else:
        ipMetas = fetch_clickhouse_ipdata(gte=gte,lt=lt, ips='only-ip',timeframe=timeframe)
    interval = 0
    if timeframe =='Daily':
        interval = 24 * 60
        redis_db = REDIS_IP_DAILY_DB
    elif timeframe == 'hourly':
        interval = 1 * 60 
        redis_db = REDIS_IP_HOURLY_DB
    elif timeframe == 'Minutly':
        interval = 5     
        redis_db = REDIS_IP_5MIN_DB 
           
    if save_ipmetas_in_redis(ipMetas, redis_db, timedelta(minutes=interval)):
        logger.debug(f"{len(ipMetas)} {timeframe} ipmetas saved  into Redis.",
                     {"state": "saved all ipmetas", "command": "remember"})

    # if save_ipmeta_in_redis_multiprocess(ipMetas, redis_db, timedelta(minutes=interval), REMEMBER_NUMBER_OF_PROCESSOR):
    #     logger.debug(f"{len(ipMetas)} {timeframe} ipmetas saved  into Redis.",
    #                  {"state": "saved all ipmetas", "command": "remember"})


def fetch_all_unlabeled_ipmetas(resolution: int, gte: str = None, lte: str = None):
    part_count = math.ceil(resolution / REMEMBER_BATCH_SIZE)
    threads = create_threads(resolution, part_count, gte, lte)
    start_threads(threads)
    initialize_sms_data()
    global global_ipmeta_count
    save_sms_data('remember', f"{global_ipmeta_count} IPMetas")
    save_keys_of_sorted_ips()
    logger.info(f"done", {"command": "remember"})


def save_keys_of_sorted_ips():
    keys = get_keys_from_redis(REDIS_IP_HOURLY_DB)
    all_unlabeled_ipmetas = load_objects_from_redis(keys, REDIS_IP_HOURLY_DB)
    all_unlabeled_ipmetas.sort(key=lambda ipmeta: pickle.loads(ipmeta).total_traffic, reverse=True)
    ips = [str(pickle.loads(ipmeta).ip) for ipmeta in all_unlabeled_ipmetas]
    if save_object_in_redis(ips, "sorted_ip_list", REDIS_TMP_DB, timedelta(days=1)):
        logger.debug(f"save sorted ip list into Redis.",
                     {"state": "saved sorted ip list", "command": "remember"})
    else:
        logger.warning("Failed to save sorted ip list into Redis.",
                       {"command": "remember"})


def start_threads(threads):
    threads_to_start = threads.copy()
    i = 0
    while len(threads_to_start) > 0:
        if threading.active_count() > 50:
            time.sleep(1)
            continue
        else:
            i += 1
            process = threads_to_start.pop(0)
            process.start()
    for process in threads:
        process.join()


def create_threads(resolution, part_count, gte, lte):
    logger.info(f"fetch_top_ips started; going to fetch {resolution} top IPs", {"command": "remember"})
    topIPs = fetch_top_ips(ELASTIC['INDEXES']['MAIN'], resolution, gte, lte)
    logger.info(f"fetch_top_ips finished: {len(topIPs)} top IPs fetched.", {"command": "remember"})
    c = Counter(topIPs.values())
    temp = sorted(topIPs.items(), key=lambda x: c[x[1]], reverse=True)
    sorted_temp = sorted(temp, key=lambda x: x[1], reverse=True)
    sorted_ips = []
    for i in range(0, len(sorted_temp)):
        sorted_ips.append(sorted_temp[i][0])
    logger.info(f"sorting ips finished", {"command": "remember"})
    ip_chunks = chunking_data(sorted_ips, part_count)
    threads = []
    for part_number in range(0, part_count):
        processes = Thread(target=fetch_and_save_ipmetas,
                           args=[ip_chunks[part_number], len(ip_chunks[part_number]), part_number, gte, lte])
        threads.append(processes)
    return threads


def fetch_and_save_ipmetas(ips, part_size, part_number, gte, lte):
    logger.debug(f"thread {part_number} get ips", {"thread": part_number, "state": "get ips", "command": "remember"})
    ip = False
    dns = False
    domain = False
    ipMetas: List[IpMeta] = produce_ipmeta(part_size, -1, 0, gte=gte, lte=lte, args=ips, id=part_number,
                                           command="remember")
    logger.debug(f"thread {part_number} generated all ipmetas.",
                 {"thread": part_number, "state": "generated all ipmetas", "command": "remember"})
    
    if save_ipmetas_in_redis(ipMetas, REDIS_IP_HOURLY_DB, timedelta(days=1)):
        ip = True
        logger.debug(f"thread {part_number} saved {len(ipMetas)} ipmetas into Redis.",
                     {"thread": part_number, "state": "saved all ipmetas", "command": "remember"})

        global global_ipmeta_count
        with thread_lock:
            global_ipmeta_count += len(ipMetas)

    dnsMetas = get_all_resolved_ips(ipMetas)
    logger.debug(f"thread {part_number} generated all dnsmetas.",
                 {"thread": part_number, "state": "generated all dnsmetas", "command": "remember"})
    if save_domainmetas_in_redis(dnsMetas, REDIS_DNS_DB, timedelta(days=7)):
        dns = True
        logger.debug(f"thread {part_number} saved all dnsmeta into Redis.",
                     {"thread": part_number, "state": "saved all dnsmeta", "command": "remember"})
    domainMetas = get_all_server_ips(ipMetas)
    logger.debug(f"thread {part_number} generated all domainMetas.",
                 {"thread": part_number, "state": "generated all domainMetas", "command": "remember"})
    if save_domainmetas_in_redis(domainMetas, REDIS_DOMAIN_DB, timedelta(days=7)):
        domain = True
        logger.debug(f"thread {part_number} saved all dnsmeta into Redis.",
                     {"thread": part_number, "state": "saved all dnsmeta", "command": "remember"})
    logger.info(f"thread {part_number} was done. Redis > ip:{ip} dns: {dns} domain: {domain}",
                {"thread": part_number, "state": "done", "command": "remember"})


def fetch_top_ips(index, count, gte, lte):
    q_top = {
        "size": 0,
        "query": {
            "range": {
                "date": {
                    "gte": gte,
                    "lte": lte
                }
            }
        },
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    "size": count,
                    "order": {
                        "traffic": "desc"
                    }
                },
                "aggs": {
                    "traffic": {
                        "sum": {
                            "field": "bsc",
                            "script": {
                                "source": "return doc['bcs'].value+doc['bsc'].value"
                            }
                        }
                    }
                }
            }
        }
    }
    top_ips = fetch_elastic(
        t_index=index,
        query=q_top,
        **ELASTIC['CREDENTIALS']
    )
    ips = {}
    for ip in top_ips:
        ips[ip.get('ip')] = (ip.get('traffic'))
    return ips


def chunking_data(data, split):
    total_size = len(data)
    p = split
    q = total_size // p
    r = total_size - split * q
    chunks = [data[(q + 1) * i:(q + 1) * (i + 1)] for i in range(r)] + [
        data[(q + 1) * r + q * i:(q + 1) * r + q * (i + 1)] for i in range(p - r)]
    return chunks
