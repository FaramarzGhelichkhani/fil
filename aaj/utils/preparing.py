import datetime
import math
import random
import numpy as np
import pandas as pd
import pytz
import ipaddress
from aaj.utils.similarity import Similarity
from aaj.utils.worker import chunking_data
from multiprocessing import Pool
from utils.ipmeta.main import check_ipmeta_completion 


def dns_features_extractor(ipmeta, data):
    count_host = len(ipmeta.dns_dist)
    com = 0
    org = 0
    net = 0
    ir  = 0
    other_tld = 0 
    number_of_consonants = 0 
    number_of_vowels = 0
    vowels= list("aeiouy")
    consonants= list("bcdfghjklmnpqrstvexz")
    subs = []
    percents = []
    hosts_length = []
    for dnsdist in ipmeta.dns_dist:
        host = dnsdist.dns
        tld = host.split('.')[-1]
        percents.append(dnsdist.percent)
        hosts_length.append(len(host))
        subs.append(dnsdist.sub)
        if tld == 'com':
                com += dnsdist.percent
        elif tld == 'org':
            org += dnsdist.percent  
        elif tld == 'net':
            net += dnsdist.percent
        elif tld == 'ir':
            ir += dnsdist.percent
        elif not tld in ['com','net','org','ir']:
            other_tld += dnsdist.percent  
            
        number_of_consonants += sum(host.count(c) for c in consonants)
        number_of_vowels += sum(host.count(c) for c in vowels)

    if count_host > 0:
        mean_percent = np.mean(percents)
        variance_percent = np.var(percents)
        mean_length = np.mean(hosts_length)
        variance_length = np.var(hosts_length)
        mean_sub = np.mean(subs)
        variance_sub = np.var(subs)
    else:
        mean_percent = 0
        variance_percent = 0
        mean_length = 0
        variance_length = 0
        mean_sub = 0
        variance_sub=0

    data["count_dns"] = count_host
    data["dns_percent_mean"] = mean_percent
    data["dns_percent_var"] = variance_percent
    data["dns_length_mean"] = mean_length
    data["dns_length_var"] = variance_length
    data["dns_tld_percent_com"] = com
    data["dns_tld_percent_org"] = org
    data["dns_tld_percent_net"] = net
    data["dns_tld_percent_ir"] = ir
    data["dns_tld_percent_other"] = other_tld
    data["dns_number_of_consonants"] = number_of_consonants
    data["dns_number_of_vowels"] = number_of_vowels
    data["dns_mean_subs"] = mean_sub
    data["dns_variance_sub"] = variance_sub
    return data


def size_features_extractor(ipmeta, data):
    ssl_sizes = []
    ssl_percent = []
    tcp_sizes = []
    tcp_percent = []
    udp_sizes = []
    udp_percent = []
    for sizedist in ipmeta.size_dist:
        if sizedist.protocol == 'ssl':
            ssl_sizes.append(int(sizedist.size))
            ssl_percent.append(sizedist.percent)
        elif sizedist.protocol == 'tcp':
            tcp_sizes.append(int(sizedist.size))
            tcp_percent.append(sizedist.percent)
        elif sizedist.protocol == 'udp':
            udp_sizes.append(int(sizedist.size))
            udp_percent.append(sizedist.percent)

    ssl_mean, ssl_var = 0, 0
    tcp_mean, tcp_var = 0, 0
    udp_mean, udp_var = 0, 0
    if len(ssl_sizes) > 0:
        ssl_mean = np.average(ssl_sizes, weights=ssl_percent)
        ssl_var = np.average((ssl_sizes - ssl_mean) ** 2, weights=ssl_percent)
    if len(tcp_sizes) > 0:
        tcp_mean = np.average(tcp_sizes, weights=tcp_percent)
        tcp_var = np.average((tcp_sizes - tcp_mean) ** 2, weights=tcp_percent)
    if len(udp_sizes) > 0:
        udp_mean = np.average(udp_sizes, weights=udp_percent)
        udp_var = np.average((udp_sizes - udp_mean) ** 2, weights=udp_percent)

    data["size_ssl_count"] = len(ssl_sizes)
    data["size_ssl_mean"] = ssl_mean
    data["size_ssl_var"] = ssl_var
    data["size_tcp_count"] = len(tcp_sizes)
    data["size_tcp_mean"] = tcp_mean
    data["size_tcp_var"] = tcp_var
    data["size_udp_count"] = len(udp_sizes)
    data["size_udp_mean"] = udp_mean
    data["size_udp_var"] = udp_var

    return data


def port_features_extractor(ipmeta, data):
    count_port = len(ipmeta.port_dist)
    none_default_port_percent = 0
    none_default_port_number = 0
    number_of_none_default_port = 0
    port443 = 0
    port80 = 0
    port53 = 0
    port0= 0
    percents = []
    for portdist in ipmeta.port_dist:
        percents.append(portdist.percent)
        if portdist.port == 443:
            port443 = portdist.percent
        elif portdist.port == 80:
            port80 = portdist.percent
        elif portdist.port == 53:
            port53 = portdist.percent
        elif portdist.port == 0:
            port0 += portdist.percent    
        elif portdist.port > 1023:
            none_default_port_percent += portdist.percent
            number_of_none_default_port += 1
    
    data["count_port"] = count_port
    data["port_mean_percent"] = np.mean(percents) if len(percents) != 0 else 0
    data["port_variance_percent"] = np.var(percents) if len(percents) != 0 else 0
    data["port443_percent"] = port443
    data["port53_percent"] = port53
    data["port80_percent"] = port80
    data["port0_percent"] = port0
    data["none_default_port_number"] = none_default_port_number
    data["none_default_port_percent"]=  none_default_port_percent

    return data

def domain_features_extractor(ipmeta, data):
    count_domain = len(ipmeta.domain_dist)
    com = 0
    org = 0
    net = 0
    ir  = 0
    other_tld = 0 
    number_of_consonants = 0 
    number_of_vowels = 0
    vowels= list("aeiouy")
    consonants= list("bcdfghjklmnpqrstvexz")
    subs = []
    ipmeta.domain_dist  = sorted(ipmeta.domain_dist, key= lambda x: x.percent , reverse=True)[0:30]
    if count_domain != 0:
        percents = []
        domains_length = []
        nulldomain_percent = 0
        for domaindist in ipmeta.domain_dist:
            domain_name = domaindist.domain
            tld = domain_name.split('.')[-1]
            percents.append(domaindist.percent)
            domains_length.append(len(domain_name))
            subs.append(domaindist.sub)
            if domain_name == 'null-domain':
                nulldomain_percent = domaindist.percent            
            if tld == 'com':
                com += domaindist.percent
            elif tld == 'org':
                org += domaindist.percent  
            elif tld == 'net':
                net += domaindist.percent
            elif tld == 'ir':
                ir += domaindist.percent
            elif not tld in ['com','net','org','ir']:
                other_tld += domaindist.percent  
            
            number_of_consonants += sum(domain_name.count(c) for c in consonants)
            number_of_vowels += sum(domain_name.count(c) for c in vowels)
        
        mean_percent = np.mean(percents)
        variance_percent = np.var(percents)
        mean_length = np.mean(domains_length)
        variance_length = np.var(domains_length)
        mean_sub = np.mean(subs)
        variance_sub = np.var(subs)
    else:
        nulldomain_percent = 0
        mean_percent = 0
        variance_percent = 0
        mean_length = 0
        variance_length = 0
        mean_sub = 0 
        variance_sub=0

    data["count_domain"] = count_domain
    data["null_domain_percent"] = nulldomain_percent
    data["domain_percent_mean"] = mean_percent
    data["domain_percent_var"] = variance_percent
    data["domain_length_mean"] = mean_length
    data["domain_length_var"] = variance_length
    data["domain_tld_percent_com"] = com
    data["domain_tld_percent_org"] = org
    data["domain_tld_percent_net"] = net
    data["domain_tld_percent_ir"] = ir
    data["domain_tld_percent_other"] = other_tld
    data["domain_number_of_consonants"] = number_of_consonants
    data["domain_number_of_vowels"] = number_of_vowels
    data["domain_mean_subs"] = mean_sub
    data["domain_variance_sub"] = variance_sub
    return data

def detection_features_extractor(ipmeta, data):
    name_dict=  {'6s':'tcp' ,'17s':'udp', '850s':'ssl', '617s':'dns',  '1122s':'https', 
    '676s':'http', '28392m': 'freeze','27459p':'Iran'}

    id_dict_percent=  {'6s':0 ,'17s': 0, '850s': 0, '617s': 0,  '1122s': 0, 
    '676s': 0, '28392m': 0,'27459p': 0}

    detect_percent = []

    for detection in ipmeta.detection_dist:
        if detection.detection in id_dict_percent:
            id_dict_percent[detection.detection] += detection.percent
        detect_percent.append(detection.percent)    
                
    for key, val in id_dict_percent.items():
        data[name_dict[key]] = val
    
    data['detect_percent'+'_mean'] = np.mean(detect_percent) 
    data['detect_percent'+'_var']  = np.var(detect_percent) 
    return data

def get_sni(ipmeta, data):
    dns_host = [dns.dns for dns in ipmeta.dns_dist]
    dom_host = [dom.domain for dom in ipmeta.domain_dist]
    common   = set(dns_host).intersection(dom_host)
    data["sni"] = len(common) 

    return data 


def get_default_data(ipmeta):
    asn = int(float(ipmeta.asn)) if ipmeta.asn != 'no asn' else 0
    total_hit = ipmeta.totalhit
    bytes_ratio = (ipmeta.totalbsc / ipmeta.totalbcs) if ipmeta.totalbcs != 0 else None
    total_traffic = (ipmeta.totalbsc + ipmeta.totalbcs)
    hit_traffic_ratio = total_traffic / total_hit  if total_hit != 0 else None
    value = int(ipaddress.ip_address(ipmeta.ip))
    data = {'ip': ipmeta.ip ,'time':ipmeta.time, 'source': ipmeta.source if hasattr(ipmeta,'source') else None , 'payload':  int(float(ipmeta.payload)) if hasattr(ipmeta,'payload') else None 
    , 'asn': str(asn) , 'total_traffic': total_traffic,
            'total_hit': total_hit, 'bytes_ratio': bytes_ratio,
            'hit_traffic_ratio': hit_traffic_ratio , 'value':value }
    return data

def features_extractor(ipmetas):
    """
    extract features 
    return list of dicts.
    """
    Data = []
    for ipmeta in ipmetas:
        data = get_default_data(ipmeta)
        data = dns_features_extractor(ipmeta, data)
        data = port_features_extractor(ipmeta, data)
        data = domain_features_extractor(ipmeta, data)
        data = detection_features_extractor(ipmeta, data)
        data = get_sni(ipmeta, data)
        # data = size_features_extractor(ipmeta, data)
        data['label'] = ipmeta.label if hasattr(ipmeta, 'label') else 'unknown'
        data["predict"] = 'no-prediction'
        Data.append(data)
    return Data


def create_data(ipmetas, return_X_y=False):
    Data = features_extractor(ipmetas)
    data_df = pd.DataFrame(data=Data)
    
    if return_X_y:
        numerical_feature_name = data_df.columns[5:-2]
        X = data_df[numerical_feature_name].values
        y = data_df['label'].values
        return X, y
    return data_df 


class Preparation:

    def __init__(self, dataset=[]):
        self.dataset = dataset
        self.paired_dataset = []

    def empty_ipmeta_drop(self):
        new_dataset = []
        self.dataset = list(filter(lambda x: check_ipmeta_completion(x[0])==True , self.dataset))

        for i in range(len(self.dataset)):
            if  self.dataset[i][0].port_dist == [] or \
                self.dataset[i][0].domain_dist == [] or \
                self.dataset[i][0].appid_dist == []:
                continue
            new_dataset.append(self.dataset[i])
        self.dataset = new_dataset

    def set_time(self, time, base_format):
        base_time = datetime.datetime.strptime(time, base_format)
        base_time = base_time.replace(tzinfo=pytz.utc)

        new_dataset = []
        for ipmeta in self.dataset:
            try:
                if ipmeta[0].time.replace(tzinfo=pytz.utc) > base_time:
                    new_dataset.append(ipmeta)
            except Exception as e:
                print(e)
        self.dataset = new_dataset

    def payload_drop(self, payload_drop_list):
        new_dataset = []
        for ipmeta in self.dataset:
            if ipmeta[1] not in payload_drop_list:
                new_dataset.append(ipmeta)
        self.dataset = new_dataset

    def duplicate_ip_drop(self):
        dict_ip_payloads = {}
        for i in range(len(self.dataset)):
            if dict_ip_payloads.get(self.dataset[i][0].ip) == None :
                dict_ip_payloads[self.dataset[i][0].ip] = [self.dataset[i][1]]
            else:
                dict_ip_payloads[self.dataset[i][0].ip].append(self.dataset[i][1])

        ip_not_duplicate = []
        for ip, payloads in dict_ip_payloads.items():
            if len(payloads) <= 1:
                ip_not_duplicate.append(ip)

        new_dataset = []
        for i in range(len(self.dataset)):
            if self.dataset[i][0].ip in ip_not_duplicate:
                new_dataset.append([self.dataset[i][0],self.dataset[i][1]])
        self.dataset = new_dataset

    def sampling_payloads(self):
        total_payloads = np.array([])
        for i in range(len(self.dataset)):
            total_payloads = np.append(total_payloads, self.dataset[i][1])

        payload_indexes = {}
        for index, payload in enumerate(total_payloads):
            if payload_indexes.get(payload) == None:
                payload_indexes[payload]=[index]
                continue
            payload_indexes[payload].append(index)

        sample_indexes = []
        for payload, indexes in payload_indexes.items():
            if len(indexes) < 10:
                sample_indexes.extend(random.sample(indexes, int(math.ceil(1*len(indexes)))))
            else:
                sample_indexes.extend(random.sample(indexes, int(math.ceil(1*len(indexes)))))

        new_dataset = []
        for index in sample_indexes:
            new_dataset.append(self.dataset[index])

        new_dataset = random.sample(new_dataset, len(new_dataset))
        self.dataset = new_dataset
        #return self.dataset

    def paired_ipmeta(self, path):
        vpns = pd.read_csv(path)['app_id']
        true_dataset = []
        false_dataset = []
        for i in range(len(self.dataset)):
            for j in range(i+1, len(self.dataset)):
                if (self.dataset[i][1] == self.dataset[j][1]):
                    true_dataset.append([self.dataset[i], self.dataset[j]])
                else:
                    if (self.dataset[i][1] not in vpns.values) and (self.dataset[j][1] not in vpns.values):
                        continue
                    else:                        
                        false_dataset.append([self.dataset[i], self.dataset[j]])

        # if len(true_dataset) < len(false_dataset):
        #     false_dataset = random.sample(false_dataset, len(true_dataset))
        # elif len(true_dataset) > len(false_dataset):
        #     true_dataset = random.sample(true_dataset, len(false_dataset))
        # else:
        #     pass

        new_dataset = true_dataset + false_dataset
        new_dataset = random.sample(new_dataset, len(new_dataset))
        self.paired_dataset = new_dataset

    
    @classmethod
    def extract_vector_similarity(cls, vector):
        result_dict = {}
        for key, value in vector.items():
            if key in ['port', 'dns', 'domain', 'appid', 'L4_dist', 'L7_dist']:
                for k, v in value.items():
                    result_dict[key+'_'+k] = v
            else:
                result_dict[key] = value
        return result_dict

    def extract_similarity(self, chunks):
        dict_result = {"ipmeta1":[], "ipmeta2":[], "tag":[], "label":[], "ip": [], 'vector_similarity':[]}
        for ipmeta in chunks:
            # if i % 1000 == 0:
            #    print(i)
            dict_result['ipmeta1'].append(ipmeta[0][0])
            dict_result['ipmeta2'].append(ipmeta[1][0])
            dict_result['tag'].append(int((ipmeta[0][1] ==  ipmeta[1][1])))
            dict_result['label'].append((ipmeta[0][1], ipmeta[1][1]))
            dict_result['ip'].append((ipmeta[0][0].ip, ipmeta[1][0].ip))    
            dict_result['vector_similarity'].append(Similarity.ip(ipmeta[0][0], ipmeta[1][0], 'ip')) 
        return dict_result

    def calculate_df_similarity(self):
        
        chunks = chunking_data(self.paired_dataset, 5)
        
        with Pool(1) as p:
            res = p.map(func=self.extract_similarity, iterable=chunks)     

        dict_result = {"ipmeta1":[], "ipmeta2":[], "tag":[], "label":[], "ip": [], 'vector_similarity':[]}
        for i in range(len(res)):
            for k, v in res[i].items():
                dict_result[k].extend(v)  
       

        df_ipmeta = pd.DataFrame(dict_result)

        df_feature = pd.DataFrame(df_ipmeta.apply(lambda x: self.extract_vector_similarity(x['vector_similarity']), axis=1).values)
        df_feature = pd.concat([df_feature.apply(lambda x: pd.Series(x[key]), axis=1) for key in df_feature], axis=1)

        df = pd.concat([df_feature, df_ipmeta[:len(df_feature)]], axis=1)
        df = df.dropna(axis=1)
        return df

