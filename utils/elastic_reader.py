import logging
import os
import sys
from typing import Dict, List

from elasticsearch import Elasticsearch, RequestsHttpConnection

logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger("ip_classification")


def get_data(query, aggregation, data=None):
    if data is None:
        data = {}
    if type(query) != dict:
        return []
    aggs = query.get("aggs")
    if aggs is None or type(aggs) != dict:
        new_data = data.copy()
        return [new_data]
    data_list = []
    end_data = {}
    has_none_bucket = False
    has_bucket = False
    exceptions = []
    for name, query_data in aggs.items():

        if aggregation.get(name) is not None and "_misk" not in name:

            aggregation_data = aggregation.get(name)
            buckets = aggregation_data.get("buckets")
            if buckets is None:

                has_none_bucket = True
                end_data[name] = aggregation_data.get("value")
                hidden_aggs = query_data.get("aggs")
                if hidden_aggs is not None:
                    for n, q in hidden_aggs.items():

                        aggregation_data = aggregation_data.get(n)

                        buckets = aggregation_data.get("buckets")
                        if buckets is None:
                            has_none_bucket = True
                            end_data[n] = aggregation_data.get("value")
        else:
            exceptions.append(name)

    if len(exceptions):
        for i in exceptions:
            del aggs[i]

    new_data = data.copy()

    for key, value in end_data.items():
        new_data[key] = value

    for name, query_data in aggs.items():

        aggregation_data = aggregation.get(name)
        buckets = aggregation_data.get("buckets")
        if buckets is None:
            aggs = query_data.get("aggs")
            if aggs is not None:
                for n, q in aggs.items():
                    aggregation_data = aggregation_data.get(n)
                    buckets = aggregation_data.get("buckets")
                    if buckets is None:
                        continue
                    for bucket in buckets:
                        key_as_string = bucket.get("key_as_string")
                        if key_as_string is None:
                            new_data[name] = bucket.get("key")
                        else:
                            new_data[name] = bucket.get("key_as_string")

                        data_list += get_data(query_data, bucket, new_data)
                        has_bucket = True

            continue
        for bucket in buckets:

            key_as_string = bucket.get("key_as_string")
            if key_as_string is None:
                new_data[name] = bucket.get("key")
            else:
                new_data[name] = bucket.get("key_as_string")

            data_list += get_data(query_data, bucket, new_data)
            has_bucket = True

    if has_bucket:
        return data_list
    if has_none_bucket:

        for key, value in data.items():
            end_data[key] = value
        dict_fields = []
        one_level_data = {}
        for key, value in end_data.items():
            if type(value) == dict:
                dict_fields.append(key)
            else:
                one_level_data[key] = value
        for dict_field in dict_fields:
            for key, value in end_data[dict_field].items():
                one_level_data[key] = value
        return [one_level_data]

    return data_list


class MyConnection(RequestsHttpConnection):
    def __init__(self, *args, **kwargs):
        proxies = kwargs.pop('proxies', {})
        super(MyConnection, self).__init__(*args, **kwargs)
        self.session.proxies = proxies


def fetch_elastic(t_index, query, scheme, user, secret, proxies, hosts, timeout):
    sys.stderr = open(os.devnull, 'w')
    data: List[Dict] = []
    try:
        es = get_elasticsearch(scheme, user, secret, proxies, hosts, timeout)
        report = es.search(index=t_index, body=query)
        if 'aggs' in query:
            data = get_data(query, report["aggregations"])
        else:
            for value in report['hits']['hits']:
                data.append(value['_source'])
    except Exception as e:
        logger.error(str(e))

    sys.stderr = sys.__stdout__
    return data


def write_to_elastic(t_index, data, scheme, user, secret, proxies, hosts, timeout):
    es: Elasticsearch = Elasticsearch(
        hosts=[f"{scheme}://{user}:{secret}@{host}" for host in hosts],
        connection_class=MyConnection,
        use_ssl=True,
        verify_certs=False,
        proxies=proxies,
        timeout=timeout
    )


def get_elasticsearch(scheme, user, secret, proxies, hosts, timeout):
    es: Elasticsearch = Elasticsearch(
        hosts=[f"{scheme}://{user}:{secret}@{host}" for host in hosts],
        connection_class=MyConnection,
        proxies=proxies,
        use_ssl=True,
        verify_certs=False,
        timeout=timeout
    )
    es.cluster.health(wait_for_status='yellow', request_timeout=100000)
    return es
