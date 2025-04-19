import json

from fil.settings import IS_HOURLY
from utils.utils import todict
from fil.settings  import REMEMBER_FETCH_SIZE

def getappquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_app = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                }, "aggs": {
                    "apps": {
                        "terms": {
                            "size": 10000,
                            "script": {
                                "source": """
                                  def a=''; a+=doc['app.app_name.keyword'].value;
                                  a+=',';
                                  a+=doc['app.app_id'].value;
                                  if(doc['app.valid'].size()!=0){a+=',';  a+=doc['app.valid'].value}                             
                                  return a
                                """
                            },
                            "order": {
                                "total_traffics": "desc"
                            }
                        },
                        "aggs": {
                            "total_traffics": {
                                "sum": {
                                    "field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"

                                }

                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_traffics", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }

    return q_app


def getdomainquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_domain = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                }, "aggs": {
                    "domain": {
                        "terms": {
                            "field": "domain_name.keyword",
                            "size": 1000,
                            "script": {
                                "source": """
                    def a=doc['domain_name.keyword'].value;
                    def len=a.length();
                    def split_path=a.splitOnToken('.');
                    def rr=split_path.length;
                    def sw=split_path[rr-1];
                    def port=sw.indexOf(':'); 
                    if(port>0){len=port; sw=sw.substring(0,len)} 
                    def final='';
                    if(rr>1){final+=split_path[rr-2];
                    final+='.';}
                    final+=sw; 
                    return final"""
                            },
                            "order": {
                                "total_traffics": "desc"
                            }
                        },
                        "aggs": {
                            "sub": {
                                "cardinality": {
                                    "field": "domain_name.keyword"
                                }
                            },
                            "total_traffics": {
                                "sum": {
                                    "field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"

                                }

                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_traffics", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }
    return q_domain


def getdnsquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_dns = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                }, "aggs": {
                    "dns": {
                        "terms": {
                            "field": "domain_name.keyword",
                            "size": 1000,
                            "script": {
                                "source": """
                                    def a=doc['domain_name.keyword'].value;
                                    def len=a.length();
                                    def split_path=a.splitOnToken('.');
                                    def rr=split_path.length;
                                    def sw=split_path[rr-1];
                                    def port=sw.indexOf(':'); 
                                    if(port>0){len=port; sw=sw.substring(0,len)} 
                                    def final='';
                                    if(rr>1){final+=split_path[rr-2];
                                    final+='.';}
                                    final+=sw; 
                                    return final"""
                            },
                            "order": {
                                "total_hits": "desc"
                            }
                        },
                        "aggs": {
                            "sub": {
                                "cardinality": {
                                    "field": "domain_name.keyword"
                                }
                            },
                            "total_hits": {
                                "sum": {
                                    "field": "hits"

                                }

                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_hits", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }
    return q_dns


def getsizequery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_dns = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                },
                "aggs": {
                    "protocol": {
                        "terms": {
                            "field": "protocol.keyword",
                            "size": 100
                        },
                        "aggs": {
                            "size": {
                                "terms": {
                                    "field": "size",
                                    "size": 1000
                                },
                                "aggs": {
                                    "traffic": {
                                        "sum": {
                                            "field": "traffic"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return q_dns


def getportquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if IS_HOURLY:
        total_traffics = {"field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"}
    else:
        total_traffics = {"field": "traffic"}

    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_port = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                }, "aggs": {
                    "port": {
                        "terms": {
                            "field": "port",
                            "size": 1000,
                            "order": {
                                "total_traffics": "desc"
                            }
                        },
                        "aggs": {
                            "total_traffics": {
                                "sum": total_traffics
                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_traffics", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }
    return q_port


def getsitequery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    total_traffics = {"field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_port = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "site_name": {
                "terms": {
                    "field": "site_name.keyword",
                    "size": 40
                },
                "aggs": {
                    "ip": {
                        "terms": {
                            "field": "ip",
                            **partion_size
                        },
                        "aggs": {
                            "Traffic": {
                                "sum": {
                                    "field": total_traffics
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return q_port


def getipstatsquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}

    q_geo = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "total": {
                "global": {},

                "aggs": {
                    "total_traffics": {
                        "sum": {
                            "field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"

                        }
                    }

                }

            },
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                },

                "aggs": {
                    "country": {
                        "terms": {
                            "field": "geoasn.country_name.keyword"
                        }},

                    "total_bsc": {
                        "sum": {
                            "field": "bsc"
                        }
                    },
                    "total_bcs": {
                        "sum": {
                            "field": "bcs"
                        }
                    },
                    "total_hits": {
                        "sum": {
                            "field": "hits"
                        }
                    },
                    "asn": {
                        "max": {
                            "field": "geoasn.asn"
                        }},
                    "ip_traffics": {
                        "sum": {
                            "field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"

                        }
                    }

                }
            }}
    }

    return q_geo


def get_insert_query(obj, additional=None):
    insert = 'INSERT INTO ipmeta () VALUES () ON CONFLICT DO NOTHING'
    columns = ''
    exp = ''
    tuples = []
    data = dict([(key, todict(value))
                 for key, value in obj.__dict__.items()
                 if not callable(value) and not key.startswith('_')])
    for key, value in data.items():
        if columns != '':
            columns = columns + ','
            exp = exp + ','
        columns = columns + str(key)
        if type(value) is list:
            exp = exp + '%s::json[]'
            tuples.append([json.dumps(x) for x in value])
        else:
            exp = exp + '%s'
            tuples.append(value)
    if not additional is None:
        for key, value in additional.items():
            if columns != '':
                columns = columns + ','
                exp = exp + ','
            columns = columns + str(key)
            exp = exp + value[0]
            tuples.append(value[1])
    return insert[0:20] + columns + insert[20:30] + exp + insert[30:], tuple(tuples)



def get_insert_query_dataset(obj, additional=None):
    insert = 'INSERT INTO dataset_ipmeta () VALUES () ON CONFLICT DO NOTHING'
    columns = ''
    exp = ''
    tuples = []
    data = dict([(key, todict(value))
                 for key, value in obj.__dict__.items()
                 if not callable(value) and not key.startswith('_')])
    for key, value in data.items():
        if columns != '':
            columns = columns + ','
            exp = exp + ','
        columns = columns + str(key)
        if type(value) is list:
            exp = exp + '%s::json[]'
            tuples.append([json.dumps(x) for x in value])
        else:
            exp = exp + '%s'
            tuples.append(value)
    if not additional is None:
        for key, value in additional.items():
            if columns != '':
                columns = columns + ','
                exp = exp + ','
            columns = columns + str(key)
            exp = exp + value[0]
            tuples.append(value[1])
    return insert[0:28] + columns + insert[28:38] + exp + insert[38:], tuple(tuples)

def getmetadataquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}

    q_geo = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"time": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                },
                "aggs": {
                    "total_duration_lte_3": {
                        "sum": {
                            "field": "duration_lte_3"
                        }
                    },
                    "total_duration_3_100": {
                        "sum": {
                            "field": "duration_3_100"
                        }
                    },
                    "total_duration_gte_100": {
                        "sum": {
                            "field": "duration_gte_100"
                        }
                    },
                    "total_total_duration": {
                        "sum": {
                            "field": "total_duration"
                        }
                    },
                    "avg_avg_duration": {
                        "avg": {
                            "field": "avg_duration"
                        }
                    },
                    "avg_var_duration": {
                        "avg": {
                            "field": "var_duration"
                        }
                    },
                    "total_traffic_lte_500": {
                        "sum": {
                            "field": "traffic_lte_500"
                        }
                    },
                    "total_traffic_500_2048": {
                        "sum": {
                            "field": "traffic_500_2048"
                        }
                    },
                    "total_traffic_2048_10240": {
                        "sum": {
                            "field": "traffic_2048_10240"
                        }
                    },
                    "total_traffic_10240_50000": {
                        "sum": {
                            "field": "traffic_10240_50000"
                        }
                    },
                    "total_traffic_gt_50000": {
                        "sum": {
                            "field": "traffic_gt_50000"
                        }
                    },
                    "total_users_lte_500": {
                        "sum": {
                            "field": "users_lte_500"
                        }
                    },
                    "total_users_500_2048": {
                        "sum": {
                            "field": "users_500_2048"
                        }
                    },
                    "total_users_2048_10240": {
                        "sum": {
                            "field": "users_2048_10240"
                        }
                    },
                    "total_users_10240_50000": {
                        "sum": {
                            "field": "users_10240_50000"
                        }
                    },
                    "total_users_gt_50000": {
                        "sum": {
                            "field": "users_gt_50000"
                        }
                    },
                    "total_total_users": {
                        "sum": {
                            "field": "total_users"
                        }
                    },
                    "total_bsc_on_bcs_lte_1": {
                        "sum": {
                            "field": "bsc_on_bcs_lte_1"
                        }
                    },
                    "total_bsc_on_bcs_1_5": {
                        "sum": {
                            "field": "bsc_on_bcs_1_5"
                        }
                    },
                    "total_bsc_on_bcs_5_20": {
                        "sum": {
                            "field": "bsc_on_bcs_5_20"
                        }
                    },
                    "total_bsc_on_bcs_20_100": {
                        "sum": {
                            "field": "bsc_on_bcs_20_100"
                        }
                    },
                    "total_bsc_on_bcs_gt_100": {
                        "sum": {
                            "field": "bsc_on_bcs_gt_100"
                        }
                    },
                    "total_null_domain_traffic": {
                        "sum": {
                            "field": "null_domain_traffic"
                        }
                    },
                    "avg_avg_length_hostname": {
                        "avg": {
                            "field": "avg_length_hostname"
                        }
                    },
                    "avg_std_length_hostname": {
                        "avg": {
                            "field": "std_length_hostname"
                        }
                    },
                    "avg_number_of_hostname": {
                        "avg": {
                            "field": "number_of_hostname"
                        }
                    },
                    "avg_number_of_conditional_hostname": {
                        "avg": {
                            "field": "number_of_conditional_hostname"
                        }
                    },
                    "avg_count_port": {
                        "avg": {
                            "field": "count_port"
                        }
                    },
                    "total_main_port_traffic": {
                        "sum": {
                            "field": "main_port_traffic"
                        }
                    },
                    "total_none_default_port_traffic": {
                        "sum": {
                            "field": "none_default_port_traffic"
                        }
                    },
                    "total_unknown_traffic": {
                        "sum": {
                            "field": "unknown_traffic"
                        }
                    },
                    "total_httpx_traffic": {
                        "sum": {
                            "field": "httpx_traffic"
                        }
                    },
                    "total_ssl_traffic": {
                        "sum": {
                            "field": "ssl_traffic"
                        }
                    },
                    "total_tcp_traffic": {
                        "sum": {
                            "field": "tcp_traffic"
                        }
                    },
                    "total_udp_traffic": {
                        "sum": {
                            "field": "udp_traffic"
                        }
                    },
                    "avg_distsize": {
                        "avg": {
                            "field": "distsize"
                        }
                    }
                }

            }}
    }
    return q_geo


def getcommentquery(iplist, time, size=0, part=0, num=0):
    partion_size = {"size": size}
    if part > 0:
        partion_size = {"include": {
            "partition": part,
            "num_partitions": num
        },
            "size": size}
    q_comment = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": iplist}}]}},
        "aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    **partion_size
                }, "aggs": {
                    "comment": {
                        "terms": {
                            "field": "comment",
                            "size": 1000,
                            "order": {
                                "total_traffics": "desc"
                            }
                        },
                        "aggs": {
                            "total_traffics": {
                                "sum": {
                                    "field": "bsc", "script": "return doc['bsc'].value+doc['bcs'].value"

                                }

                            },
                            "total_hits": {
                                "sum": {
                                    "field": "hits"

                                }

                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_traffics", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }
    return q_comment

def clickhouse_fetch_query(gte,lt,ips=[],timeframe='hourly'):
    if ips ==[] and timeframe == 'Daily':
        query = f"""select ip, date as time , asn_id as asn, total_traffics, total_bsc, total_bcs, total_hits, 
                    appid_dist, domain_dist, port_dist, dns_dist, site_dist, detection_dist, action_dist 
                    from {timeframe}.ipmeta 
                    where date >= '{gte}' and  date < '{lt}'
                    and appid_dist is not null and domain_dist is not null and port_dist is  not null 
                    and detection_dist is not null 
                    order by total_traffics desc limit {REMEMBER_FETCH_SIZE}
                    """
    elif ips ==[] and timeframe != 'Daily':
        query = f"""select ip, date as time , asn_id as asn, total_traffics, total_bsc, total_bcs, total_hits, 
                    appid_dist, domain_dist, port_dist, dns_dist, site_dist, detection_dist, action_dist 
                    from {timeframe}.ipmeta 
                    where date >= '{gte}' and  date < '{lt}'
                    and appid_dist is not null and domain_dist is not null and port_dist is  not null 
                    and detection_dist is not null and not detection_dist like '%27459%'
                    order by total_traffics desc --limit {REMEMBER_FETCH_SIZE}
                    """                
    elif ips=='only-ip':
        query = f"""select ip
                    from {timeframe}.ipmeta 
                    where date >= '{gte}' and  date < '{lt}'
                    and appid_dist is not null and domain_dist is not null and port_dist is  not null 
                    and detection_dist is not null
                    order by total_traffics desc limit {REMEMBER_FETCH_SIZE}
                """                    
    else:
        clickhouse_array = f"({','.join(map(lambda x: f'{x!r}', ips))})"
        query = f"""select ip, date as time , asn_id as asn, total_traffics, total_bsc, total_bcs, total_hits, 
                    appid_dist, domain_dist, port_dist, dns_dist, site_dist, detection_dist, action_dist 
                    from {timeframe}.ipmeta 
                    where date  >= '{gte}' and  date < '{lt}'
                    and ip in {clickhouse_array}
                    and appid_dist is not null and domain_dist is not null and port_dist is  not null
                    """
    return query
    