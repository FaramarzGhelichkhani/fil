import numpy as np
from sklearn.preprocessing import MinMaxScaler

from fil.settings import IS_HOURLY


def get_default_data(ipmeta):
    country = ipmeta.country
    asn = int(ipmeta.asn) if ipmeta.asn != 'no asn' else 0
    asn_iran = 1 if country == 'Iran' else 0
    total_hit = ipmeta.totalhit
    bytes_ratio = (ipmeta.totalbsc / ipmeta.totalbcs) if ipmeta.totalbcs != 0 else 0
    total_traffic = (ipmeta.totalbsc + ipmeta.totalbcs)
    hit_traffic_ratio = total_traffic / total_hit
    data = {'ip': ipmeta.ip, 'asn': str(asn), 'asn_iran': asn_iran, 'total_traffic': total_traffic,
            'total_hit': total_hit, 'bytes_ratio': bytes_ratio,
            'hit_traffic_ratio': hit_traffic_ratio}
    return data


def domain_features_extractor(ipmeta, data):
    count_domain = len(ipmeta.domain_dist)
    if count_domain != 0:
        percents = []
        domains_length = []
        nulldomain_percent = 0
        for domaindist in ipmeta.domain_dist:
            domain_name = domaindist.domain
            percents.append(domaindist.percent)
            domains_length.append(len(domain_name))
            if domain_name == 'null-domain':
                nulldomain_percent = domaindist.percent
            mean_percent = np.mean(percents)
            variance_percent = np.var(percents)
            mean_length = np.mean(domains_length)
            variance_length = np.var(domains_length)
    else:
        nulldomain_percent = 0
        mean_percent = 0
        variance_percent = 0
        mean_length = 0
        variance_length = 0

    data["count_domain"] = count_domain
    data["null_domain_percent"] = nulldomain_percent
    data["domain_percent_mean"] = mean_percent
    data["domain_percent_var"] = variance_percent
    data["domain_length_mean"] = mean_length
    data["domain_length_var"] = variance_length

    return data


def dns_features_extractor(ipmeta, data):
    count_host = len(ipmeta.dns_dist)
    percents = []
    hosts_length = []
    for dnsdist in ipmeta.dns_dist:
        host = dnsdist.dns
        percents.append(dnsdist.percent)
        hosts_length.append(len(host))

    if count_host > 0:
        mean_percent = np.mean(percents)
        variance_percent = np.var(percents)
        mean_length = np.mean(hosts_length)
        variance_length = np.var(hosts_length)
    else:
        mean_percent = 0
        variance_percent = 0
        mean_length = 0
        variance_length = 0

    data["count_dns"] = count_host
    data["dns_percent_mean"] = mean_percent
    data["dns_percent_var"] = variance_percent
    data["dns_length_mean"] = mean_length
    data["dns_length_var"] = variance_length

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
    for portdist in ipmeta.port_dist:
        if portdist.port == 443:
            port443 = portdist.percent
        elif portdist.port == 80:
            port80 = portdist.percent
        elif portdist.port == 53:
            port53 = portdist.percent
        elif portdist.port > 1023:
            none_default_port_percent += portdist.percent
            number_of_none_default_port += 1

    data["count_port"] = count_port
    data["port443"] = port443
    data["port53"] = port53
    data["port80"] = port80
    data["none_default_port_number"] = none_default_port_number
    data["none_default_port_percent"] = none_default_port_percent

    return data


def get_hourly_data(ipmeta, data):
    # duration
    data['duration_lte_3'] = ipmeta.duration_lte_3
    data['duration_3_100'] = ipmeta.duration_3_100
    data['duration_gte_100'] = ipmeta.duration_gte_100
    data['total_duration'] = ipmeta.total_duration
    data['avg_duration'] = ipmeta.avg_duration
    data['var_duration'] = ipmeta.var_duration
    #  byte
    data['traffic_lte_500'] = ipmeta.traffic_lte_500
    data['traffic_500_2048'] = ipmeta.traffic_500_2048
    data['traffic_2048_10240'] = ipmeta.traffic_2048_10240
    data['traffic_10240_50000'] = ipmeta.traffic_10240_50000
    data['traffic_gt_50000'] = ipmeta.traffic_gt_50000
    # phonenum
    data['users_lte_500'] = ipmeta.users_lte_500
    data['users_500_2048'] = ipmeta.users_500_2048
    data['users_2048_10240'] = ipmeta.users_2048_10240
    data['users_10240_50000'] = ipmeta.users_10240_50000
    data['users_gt_50000'] = ipmeta.users_gt_50000
    data['total_users'] = ipmeta.total_users
    # bytes ratio layers
    data['bsc_on_bcs_lte_1'] = ipmeta.bsc_on_bcs_lte_1
    data['bsc_on_bcs_1_5'] = ipmeta.bsc_on_bcs_1_5
    data['bsc_on_bcs_5_20'] = ipmeta.bsc_on_bcs_5_20
    data['bsc_on_bcs_20_100'] = ipmeta.bsc_on_bcs_20_100
    data['bsc_on_bcs_gt_100'] = ipmeta.bsc_on_bcs_gt_100
    # domain name
    data['null_domain_traffic'] = ipmeta.null_domain_traffic
    data['avg_length_hostname'] = ipmeta.avg_length_hostname
    data['std_length_hostname'] = ipmeta.std_length_hostname
    data['number_of_hostname'] = ipmeta.number_of_hostname
    data['number_of_conditional_hostname'] = ipmeta.number_of_conditional_hostname
    # port
    data['count_port'] = ipmeta.count_port
    data['main_port_traffic'] = ipmeta.main_port_traffic
    data['none_default_port_traffic'] = ipmeta.none_default_port_traffic

    # appid
    data['unknown_traffic'] = ipmeta.unknown_traffic
    data['httpx_traffic'] = ipmeta.httpx_traffic
    data['ssl_traffic'] = ipmeta.ssl_traffic
    data['tcp_traffic'] = ipmeta.tcp_traffic
    data['udp_traffic'] = ipmeta.udp_traffic
    # size
    data['count_size'] = ipmeta.distsize

    return data


def create_data_hourly(ipmetas):
    Data = []
    for ipmeta in ipmetas:
        data = get_default_data(ipmeta)
        data = get_hourly_data(ipmeta=ipmeta, data=data)
        data['label'] = ipmeta.label if hasattr(ipmeta, 'label') else 'unknown'
        data["label"] = 'white' if data['asn_iran'] == 1 else data["label"]
        data["predict"] = 'no-prediction'
        Data.append(data)
    return data


def create_data(ipmetas):
    if IS_HOURLY:
        return create_data_hourly(ipmetas)
    else:
        Data = []
        for ipmeta in ipmetas:
            data = get_default_data(ipmeta)
            data = dns_features_extractor(ipmeta, data)
            data = port_features_extractor(ipmeta, data)
            data = domain_features_extractor(ipmeta, data)
            data = size_features_extractor(ipmeta, data)

            data['label'] = ipmeta.label if hasattr(ipmeta, 'label') else 'unknown'
            data["label"] = 'white' if data['asn_iran'] == 1 else data["label"]
            data["predict"] = 'no-prediction'
            Data.append(data)
        return Data


def prepration(dataframe):
    numeric_features = dataframe.select_dtypes(include=['int64', 'float64']).columns.values
    raw_x = dataframe[numeric_features]

    X_raw = raw_x.to_numpy()
    Y = dataframe["label"].to_numpy()
    trans = MinMaxScaler()
    X = trans.fit_transform(X_raw)
    return (X, Y)
