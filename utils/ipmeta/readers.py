import logging
from typing import List

import psycopg2

from fil.settings import DB_HOST_SIZE, DB_NAME_SIZE, DB_USER_SIZE, \
    DB_PASSWORD_SIZE
from utils.ipmeta.classes import AppDist, DnsDist, DomainDist, IpMeta, PortDist, SizeDist, SiteDist, ActiontDist, DetectionDist

logger = logging.getLogger("ip_classification.main")


def readerport(listofip: List[IpMeta], portdic):
    port = []
    for dic in portdic:
        try:
            port.append((dic['ip'], PortDist(
                port=dic['port'], percent=dic['percent'], traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']  )))
        except:
            continue
    return adddatatoclass(listofip, port, 'port_dist')


def readeripstats(ipstatslist, date, metadatalist=[]) -> List[IpMeta]:
    iplist = []
    metadatadict = {}
    for item in metadatalist:
        metadatadict[item['ip']] = item
    for dic in ipstatslist:
        try:
            if dic['ip'] not in metadatadict.keys():
                iplist.append(
                    IpMeta(
                        ip=dic['ip'],
                        asn='no asn' if ('asn' not in dic.keys() or dic['asn'] is None) else dic['asn'],
                        traffic=dic['ip_traffics'],
                        bsc=dic['total_bsc'],
                        bcs=dic['total_bcs'],
                        hit=dic['total_hits'],
                        percent=dic['ip_traffics'] / dic['total_traffics'],
                        country='no country' if ('country' not in dic.keys() or dic['country'] is None) else dic[
                            'country'],
                        time=date['gte']
                    )
                )
            else:
                iplist.append(
                    IpMeta(
                        ip=dic['ip'], asn='no asn' if ('asn' not in dic.keys() or dic['asn'] is None) else dic['asn'],
                        traffic=dic['ip_traffics'], bsc=dic['total_bsc'],
                        bcs=dic['total_bcs'],
                        hit=dic['total_hits'], percent=dic['ip_traffics'] / dic['total_traffics'],
                        country='no country' if ('country' not in dic.keys() or dic['country'] is None) else dic[
                            'country'],
                        time=date['gte'],
                        duration_lte_3=safe_int(metadatadict[dic['ip']]['total_duration_lte_3']),
                        duration_3_100=safe_int(metadatadict[dic['ip']]['total_duration_3_100']),
                        duration_gte_100=safe_int(metadatadict[dic['ip']]['total_duration_gte_100']),
                        total_duration=safe_int(metadatadict[dic['ip']]['total_total_duration']),
                        avg_duration=safe_float(metadatadict[dic['ip']]['avg_avg_duration']),
                        var_duration=safe_float(metadatadict[dic['ip']]['avg_var_duration']),
                        traffic_lte_500=safe_int(metadatadict[dic['ip']]['total_traffic_lte_500']),
                        traffic_500_2048=safe_int(metadatadict[dic['ip']]['total_traffic_500_2048']),
                        traffic_2048_10240=safe_int(metadatadict[dic['ip']]['total_traffic_2048_10240']),
                        traffic_10240_50000=safe_int(metadatadict[dic['ip']]['total_traffic_10240_50000']),
                        traffic_gt_50000=safe_int(metadatadict[dic['ip']]['total_traffic_gt_50000']),
                        users_lte_500=safe_int(metadatadict[dic['ip']]['total_users_lte_500']),
                        users_500_2048=safe_int(metadatadict[dic['ip']]['total_users_500_2048']),
                        users_2048_10240=safe_int(metadatadict[dic['ip']]['total_users_2048_10240']),
                        users_10240_50000=safe_int(metadatadict[dic['ip']]['total_users_10240_50000']),
                        users_gt_50000=safe_int(metadatadict[dic['ip']]['total_users_gt_50000']),
                        total_users=safe_int(metadatadict[dic['ip']]['total_total_users']),
                        bsc_on_bcs_lte_1=safe_int(metadatadict[dic['ip']]['total_bsc_on_bcs_lte_1']),
                        bsc_on_bcs_1_5=safe_int(metadatadict[dic['ip']]['total_bsc_on_bcs_1_5']),
                        bsc_on_bcs_5_20=safe_int(metadatadict[dic['ip']]['total_bsc_on_bcs_5_20']),
                        bsc_on_bcs_20_100=safe_int(metadatadict[dic['ip']]['total_bsc_on_bcs_20_100']),
                        bsc_on_bcs_gt_100=safe_int(metadatadict[dic['ip']]['total_bsc_on_bcs_gt_100']),
                        null_domain_traffic=safe_int(metadatadict[dic['ip']]['total_null_domain_traffic']),
                        avg_length_hostname=safe_float(metadatadict[dic['ip']]['avg_avg_length_hostname']),
                        std_length_hostname=safe_float(metadatadict[dic['ip']]['avg_std_length_hostname']),
                        number_of_hostname=safe_float(metadatadict[dic['ip']]['avg_number_of_hostname']),
                        number_of_conditional_hostname=safe_float(
                            metadatadict[dic['ip']]['avg_number_of_conditional_hostname']),
                        count_port=safe_float(metadatadict[dic['ip']]['avg_count_port']),
                        main_port_traffic=safe_int(metadatadict[dic['ip']]['total_main_port_traffic']),
                        none_default_port_traffic=safe_int(metadatadict[dic['ip']]['total_none_default_port_traffic']),
                        unknown_traffic=safe_int(metadatadict[dic['ip']]['total_unknown_traffic']),
                        httpx_traffic=safe_int(metadatadict[dic['ip']]['total_httpx_traffic']),
                        ssl_traffic=safe_int(metadatadict[dic['ip']]['total_ssl_traffic']),
                        tcp_traffic=safe_int(metadatadict[dic['ip']]['total_tcp_traffic']),
                        udp_traffic=safe_int(metadatadict[dic['ip']]['total_udp_traffic']),
                        distsize=safe_float(metadatadict[dic['ip']]['avg_distsize'])
                    )
                )
        except:
            pass
    return iplist


def readerapp(listofip: List[IpMeta], appdic):
    app = []
    for dic in appdic:
        if 'apps' in dic and  (dic['apps'].split(',')[1].isnumeric()):
            app.append(
                (
                    dic['ip'],
                    AppDist(
                        app_name=dic['apps'].split(',')[0],
                        valid=None if len(dic['apps'].split(',')) < 3 else dic['apps'].split(',')[2],
                        traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']  ,
                        app_id=dic['apps'].split(',')[1],
                        percent=dic['percent'],
                    )

                )
            )
        elif 'app_name' in  dic:
            app.append(
                (
                    dic['ip'],
                    AppDist(
                        app_name=dic['app_name'],
                        traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']  ,
                        app_id=dic['app_id'],
                        percent=dic['percent'],
                    )

                )
            )
        else:
            app.append(
                (
                    dic['ip'],
                    AppDist(
                        app_name=dic['apps'].split(',')[0],
                        valid=None if len(dic['apps'].split(',')) < 3 else dic['apps'].split(',')[2],
                        traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic'] ,
                        percent=dic['percent'])
                )
            )
    return adddatatoclass(listofip, app, 'appid_dist')


def readerdns(listofip: List[IpMeta], dnsdic):
    dns = []
    for dic in dnsdic:
        try:
            dns.append((dic['ip'], DnsDist(
                dns=dic['dns'], hit=dic['total_hits'] if 'total_hits' in dic else dic['hit']  , sub=dic['sub'], percent=dic['percent'])))
        except:
            continue        
    return adddatatoclass(listofip, dns, 'dns_dist')


def readersize(listofip: List[IpMeta], sizedic):
    ip_total_traffic = {}
    for dic in sizedic:
        ip = dic['ip']
        if ip not in ip_total_traffic.keys():
            ip_total_traffic[ip] = 0
        ip_total_traffic[ip] += dic['traffic']

    size = []
    for dic in sizedic:
        dic['percent'] = dic['traffic'] / ip_total_traffic[dic['ip']]
        size.append((dic['ip'], SizeDist(
            protocol=dic['protocol'], traffic=dic['traffic'], size=dic['size'], percent=dic['percent'])))
    return adddatatoclass(listofip, size, 'size_dist')


def readerdomain(listofip: List[IpMeta], domaindic):
    domain = []
    for dic in domaindic:
        try:
            domain.append((dic['ip'], DomainDist(
                domain=dic['domain'], traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']  , sub=dic['sub'], percent=dic['percent'])))
        except:
            continue
    return adddatatoclass(listofip, domain, 'domain_dist')


def adddatatoclass(listofip: List[IpMeta], tuple, type):
    for x in tuple:
        for ip in listofip:
            if ip.ip == x[0]:
                getattr(ip, type).append(x[1])
                break
    return True


def readsize(ip_list, date):
    date = date + ',  00:00'
    con = psycopg2.connect(host=DB_HOST_SIZE, database=DB_NAME_SIZE,
                           user=DB_USER_SIZE,
                           password=DB_PASSWORD_SIZE)
    cur = con.cursor()
    cur.execute("SELECT ip, sizedist from sizedist1day where ip =  any('{ips}') and time ='{time}' ".format(
        ips='{' + ','.join(ip_list) + '}', time=date))
    data = cur.fetchall()
    result = {}
    for row in data:
        ip = row[0]
        result[ip] = []
        for sizedict in row[1]:
            protocol = sizedict['f1']
            size = sizedict['f2']
            traffic = sizedict['f3']
            percent = sizedict['f4']
            sizeDist = SizeDist(protocol, size, traffic, percent)
            result[ip].append(sizeDist)
    return result


def addsizetoclass(IpMetas: List[IpMeta], sizedicts):
    for ip in IpMetas:
        if ip.ip in sizedicts:
            ip.size_dist = sizedicts[ip.ip]

def safe_int(val):
    try:
        return 0 if val in ['None', 'NoneType', None] else int(val)
    except Exception as e:
        print(e)
        print(f"val:{val}")
        print(f"type(val):{type(val)}")


def safe_float(val):
    try:
        return 0 if val in ['None', 'NoneType', None] else float(val)
    except Exception as e:
        print(e)
        print(f"val:{val}")
        print(f"type(val):{type(val)}")

def readersite(listofip: List[IpMeta], sitedic):
    site = []
    for dic in sitedic:
        site.append((dic['ip'], SiteDist(
            site_name=dic['site_name'], percent=dic['percent'], traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']    )))
    return adddatatoclass(listofip, site, 'site_dist')

def readeraction(listofip: List[IpMeta], actiondic):
    action = []
    for dic in actiondic:
        action.append((dic['ip'], ActiontDist(
            action=dic['action'], percent=dic['percent'], traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic']  )))
    return adddatatoclass(listofip, action, 'action_dist')

def readerdetection(listofip: List[IpMeta], detectiondic):
    detection = []
    for dic in detectiondic:
        detection.append((dic['ip'], DetectionDist(
            detection=dic['detection'], percent=dic['percent'], traffic=dic['total_traffics'] if 'total_traffics' in dic else dic['traffic'] )))
    return adddatatoclass(listofip, detection, 'detection_dist')    
