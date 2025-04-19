import json
import logging
import pickle
from typing import Dict, List

from fil.settings import ELASTIC, IS_HOURLY
from utils.clik_house_reader import fetch_clickhouse_ipdata, fetch_clickhouse_ipdata_multiprocess
from utils.elastic_reader import fetch_elastic
from utils.ipmeta.classes import AppDist, DetectionDist, IpMeta, PortDist, ResolvedIP, ServerIP, DomainMeta, DomainDist,DnsDist
from utils.ipmeta.queries import ( getappquery, getdnsquery, getdomainquery, getipstatsquery, getportquery,
                                  getmetadataquery, getsizequery)
from utils.ipmeta.readers import (readerdns, readerdomain, readerapp, readeripstats, readerport,
                                  readersize)
from utils.utils import todict_digest

logger = logging.getLogger("ip_classification")


def produce_ipmeta(size: int = 0, part: int = 0, num: int = 0, gte: str = None, lte: str = None, args: List[str] = [],
                   id: int = -1, command: str = ''): 
    sample_ip: List[str] = args
    date: Dict = {}
    if gte:
        date['gte'] = gte
    if lte:
        date['lte'] = lte
    q_ipstats = getipstatsquery(sample_ip, date, size, part, num)
    ipstats = fetch_elastic(
        t_index=ELASTIC['INDEXES']['MAIN'],
        query=q_ipstats,
        **ELASTIC['CREDENTIALS']
    )
    log_message = f"app/thread {id} fetch ip stats"
    logger.debug(log_message, {"thread": id, "state": "fetch ip stats", "command": command})
    ip_metas: List[IpMeta] = []
    if IS_HOURLY:
        q_metadata = getmetadataquery(sample_ip, date, size, part, num)
        metalist = fetch_elastic(
            t_index=ELASTIC['INDEXES']['META'],
            query=q_metadata,
            **ELASTIC['CREDENTIALS']
        )
        log_message = f"app/thread {id} fetch meta"
        logger.debug(log_message, {"thread": id, "state": "fetch meta", "command": command})
        ip_metas = readeripstats(ipstats, date, metalist)
    else:
        ip_metas = readeripstats(ipstats, date)
    len_IPStats = len(ip_metas)
    fetch_and_add_to_ipmetas_lambda = lambda index, name, get_query, reader: fetch_and_add_to_ipmetas(id, sample_ip,
                                                                                                      date, size, part,
                                                                                                      num, ip_metas,
                                                                                                      command, index,
                                                                                                      name, get_query,
                                                                                                      reader)
    len_APP = fetch_and_add_to_ipmetas_lambda('MAIN', 'apps', getappquery, readerapp)
    len_DNS = fetch_and_add_to_ipmetas_lambda('DNS', 'dnss', getdnsquery, readerdns)
    len_PORT = fetch_and_add_to_ipmetas_lambda('PORT', 'ports', getportquery, readerport)
    len_DOMAIN = fetch_and_add_to_ipmetas_lambda('MAIN', 'domains', getdomainquery, readerdomain)
    if IS_HOURLY:
        pass
    else:
        fetch_and_add_to_ipmetas_lambda('SIZE', 'sizes', getsizequery, readersize)
    if command == 'test':
        for ipmeta in ip_metas:
            print(json.dumps(todict_digest(ipmeta), indent=4))
    logger.debug(
        f"sample_ip: {len(sample_ip)}, IPStats: {len_IPStats}, APP: {len_APP}, DNS: {len_DNS}, PORT: {len_PORT}, DOMAIN: {len_DOMAIN}",
        {"state": "done", "command": "remember"})
    logger.debug(f"diff: {set(sample_ip).difference(set([x.ip for x in ip_metas]))}",
                 {"state": "done", "command": "remember"})
    return ip_metas


def fetch_and_add_to_ipmetas(id, sample_ip, date, size, part, num, ip_metas, command, index, name, get_query, reader):
    query = get_query(sample_ip, date, size, part, num)
    if command == 'test':
        print(index + '    ######################################################################')
        s = f"query:\n{json.dumps(query, indent=4)}"
        print(s.replace('\\n', '\n'))
    datalist = fetch_elastic(
        t_index=ELASTIC['INDEXES'][index],
        query=query,
        **ELASTIC['CREDENTIALS']
    )
    if command == 'test':
        print(f"datalist:\n{json.dumps(datalist, indent=4)}")
    logger.debug(f"app/thread {id} fetch {name}", {"thread": id, "state": f"fetch {name}", "command": command})
    reader(ip_metas, datalist)
    return len(datalist)


def get_all_resolved_ips(ipmeta_list):
    return [(f"{dns.dns}>{ipmeta.ip}",
             ResolvedIP(ip=ipmeta.ip, asn=ipmeta.asn, country=ipmeta.country, percent=dns.percent, hit=dns.hit,
                        sub=dns.sub, time=ipmeta.time)) for ipmeta in ipmeta_list for dns in ipmeta.dns_dist]


def get_all_server_ips(ipmeta_list):
    return [(f"{domain.domain}>{ipmeta.ip}",
             ServerIP(ip=ipmeta.ip, asn=ipmeta.asn, country=ipmeta.country, percent=domain.percent,
                      traffic=domain.traffic, sub=domain.sub, time=ipmeta.time)) for ipmeta in ipmeta_list for domain in
            ipmeta.domain_dist]


def get_domain_meta(domain, resolved_ips, server_ips):
    return DomainMeta(domain=domain, resolved_ips=[pickle.loads(item) for item in resolved_ips],
                      server_ips=[pickle.loads(item) for item in server_ips])


def check_ipmeta_completion(ipmeta,attribute_name=None):
    if attribute_name is None:
        if IS_HOURLY:
            attributes = ['domain_dist', 'port_dist', 'appid_dist']
        else:
            attributes = ['domain_dist', 'port_dist', 'appid_dist']
        missing_attributes = [attr for attr in attributes if not getattr(ipmeta, attr)]
        
        if missing_attributes:
            logger.debug(f"Missing attributes: {', '.join(missing_attributes)}")
            return False
        else:
            logger.debug("All data are present.")
            return True
    else:
        if hasattr(ipmeta, attribute_name):
            if attribute_name == 'dns_dist':
                logger.debug(f"about {attribute_name} I cant guarantee.")
                return True
            if getattr(ipmeta, attribute_name) :
                logger.debug(f"{attribute_name} is present.")
                return True
            else:
                logger.debug(f"{attribute_name} has no data.")
                return False 
        else:
            logger.debug(f"Attribute {attribute_name} does not exist.")
            return False


def produce_ipmeta_clickhouse( gte: str = None, lt: str = None,ips=[],timeframe='hourly', processor_number=10):
    # ipmetalist = fetch_clickhouse_ipdata(gte,lt,ips,timeframe)
    ipmetalist = fetch_clickhouse_ipdata_multiprocess(gte,lt,ips,timeframe, processor_number)
    logger.info(f'{len(ipmetalist)} {timeframe} ipmeta produced for {gte}.')
    return ipmetalist 

def ipmeta_aggregator(ipmetas, key_type='ip'):
    aggregated_ipmetas = {}
    dists ={}
    for ipmeta in ipmetas:
        if key_type == 'ip':
            key = ipmeta.ip
            ip = key
        else:
            key = ipmeta.asn
            ip = 'asn-aggregated'    
        aggregated_ipmetas.setdefault(key,\
            IpMeta(ip=ip,asn=ipmeta.asn,country=ipmeta.country,\
                 percent=None,bsc=0, bcs=0, hit=0,traffic=0,time=[]))
        # time
        aggregated_ipmetas[key].time.append(ipmeta.time)    
        # numerical 
        aggregated_ipmetas[key].totalbsc += ipmeta.totalbsc    
        aggregated_ipmetas[key].totalbcs += ipmeta.totalbcs    
        aggregated_ipmetas[key].totalhit += ipmeta.totalhit    
        aggregated_ipmetas[key].total_traffic += ipmeta.total_traffic
        #dists
        dists.setdefault(key,{'domain':[], 'dns':[],\
             'appid':[], 'port':[], 'detection':[]})
        dists[key]['domain'].extend(ipmeta.domain_dist)         
        dists[key]['port'].extend(ipmeta.port_dist)         
        dists[key]['dns'].extend(ipmeta.dns_dist)         
        dists[key]['detection'].extend(ipmeta.detection_dist)         
        dists[key]['appid'].extend(ipmeta.appid_dist)

    for k in dists.keys():
        domain_dist = domain_aggregator(dists[k]['domain'],  aggregated_ipmetas[k].total_traffic)             
        port_dist = port_aggregator(dists[k]['port'], aggregated_ipmetas[k].total_traffic)             
        dns_dist = dns_aggregator(dists[k]['dns'], aggregated_ipmetas[k].totalhit)             
        appid_dist = appid_aggregator(dists[k]['appid'], aggregated_ipmetas[k].total_traffic)             
        detection_dist = detection_aggregator(dists[k]['detection'], aggregated_ipmetas[k].total_traffic)

        aggregated_ipmetas[k].domain_dist = domain_dist             
        aggregated_ipmetas[k].port_dist   = port_dist             
        aggregated_ipmetas[k].dns_dist    = dns_dist             
        aggregated_ipmetas[k].appid_dist  = appid_dist             
        aggregated_ipmetas[k].detection_dist = detection_dist


    return list(aggregated_ipmetas.values())

def domain_aggregator(domain_dist, total_traffic):
    aggregated_domaindists = {}
    for dom in domain_dist:
        domain = dom.domain
        aggregated_domaindists.setdefault(domain,\
            DomainDist(domain=domain,percent=[], traffic=0, sub=[]))
        aggregated_domaindists[domain].traffic += dom.traffic    
        aggregated_domaindists[domain].sub.append(dom.sub)    

    for obj in aggregated_domaindists.values():
        obj.percent = obj.traffic / total_traffic
        obj.sub = max(obj.sub)

    return list(aggregated_domaindists.values())

def dns_aggregator(dns_dist, totalhit):
    aggregated_dnsdists = {}
    for dnsdist in dns_dist:
        dns = dnsdist.dns
        aggregated_dnsdists.setdefault(dns,\
            DnsDist(dns=dns,percent=[], hit=0, sub=[]))
        aggregated_dnsdists[dns].hit += dnsdist.hit    
        aggregated_dnsdists[dns].sub.append(dnsdist.sub)    

    for obj in aggregated_dnsdists.values():
        obj.percent = obj.hit / totalhit
        obj.sub = max(obj.sub)

    return list(aggregated_dnsdists.values())

def port_aggregator(port_dist, total_traffic):
    aggregated_portdists = {}
    for portdist in port_dist:
        port = portdist.port
        aggregated_portdists.setdefault(port,\
            PortDist(port=port,percent=[], hit=0, traffic=0))
        aggregated_portdists[port].hit += portdist.hit  if portdist.hit is not None else 0
        aggregated_portdists[port].traffic += portdist.traffic  if portdist.traffic is not None else 0

    for obj in aggregated_portdists.values():
        obj.percent = obj.traffic / total_traffic

    return list(aggregated_portdists.values())

def appid_aggregator(appid_dist, total_traffic):
    aggregated_appiddists = {}
    for appiddist in appid_dist:
        app_id = appiddist.app_id
        aggregated_appiddists.setdefault(app_id,\
            AppDist(app_id=app_id,app_name = appiddist.app_name,\
                percent=[], traffic=0))
        aggregated_appiddists[app_id].traffic += appiddist.traffic    

    for obj in aggregated_appiddists.values():
        obj.percent = obj.traffic / total_traffic

    return list(aggregated_appiddists.values())

def detection_aggregator(detection_dist, total_traffic):
    aggregated_detectiondists = {}
    for detectiondist in detection_dist:
        detection = detectiondist.detection
        aggregated_detectiondists.setdefault(detection,\
            DetectionDist(detection=detection,percent=[], traffic=0))
        aggregated_detectiondists[detection].traffic += detectiondist.traffic    

    for obj in aggregated_detectiondists.values():
        obj.percent = obj.traffic / total_traffic

    return list(aggregated_detectiondists.values())
