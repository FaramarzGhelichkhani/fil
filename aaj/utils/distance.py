import logging
from math import log as mlog, sqrt, log2
from typing import List

import numpy as np
from scipy.spatial import distance

from utils.ipmeta.classes import IpMeta
from multiprocessing import Pool
import pickle

logger = logging.getLogger("ip_classification.distance")

class DefaultValue:
    DOMAIN = ['null-domain', 'aggregated-domain']
    PORT = [0]
    APPID = [None]
    DNS = []
    L7_DIST = []
    L4_DIST = []
    SITE = []

class Distance:

    @classmethod
    def calculate_ratio(cls, aggregate_dict):
        total_ratio = 0
        
        if len(aggregate_dict.values()) == 0:
            return None

        for list_value_per_same_key in aggregate_dict.values():
            value1 = list_value_per_same_key[0]
            value2 = list_value_per_same_key[1]
            each_key = min(value1, value2) / max(value1, value2) if max(value1, value2) != 0 else 0  
            total_ratio += each_key
        
        # change len(aggregate_dict.values to counts)
        return round(total_ratio/len(aggregate_dict.values()), 6)

    @classmethod
    def jensen_shannon(cls, aggregate_dict):
        PMQx_list = []
        for i in aggregate_dict.values():
            Mx = (float(i[0]) + float(i[1]))/2
            PMQx_list.append([float(i[0]), Mx, float(i[1])])

        PM_list = []
        QM_list = []
        for i in PMQx_list:
            PM_list.append([i[0], i[1]])
            QM_list.append([i[2], i[1]])

        sum1 = cls.kullback_leibler(PM_list)
        sum2 = cls.kullback_leibler(QM_list)
    
        return round((sum1 + sum2)/2, 6)

    @classmethod
    def kullback_leibler(cls, list):
        sum = 0 
        for i in list:
            Pi = i[0]
            Qi = i[1]
            if float(Pi) == 0.0:
                sum += 0.0
                continue
            tmp = float(Pi) * log2(float(Pi) / float(Qi))
            sum += tmp

        return sum

    @classmethod
    def drop_default_value_ratio(cls, aggregate_dict, dist_metric):
        if len(aggregate_dict.keys()) == 0:
            return 1

        default_value = getattr(DefaultValue, dist_metric.upper())
        drop_keys = []
        for key in aggregate_dict.keys():
            if key in default_value:
                drop_keys.append(key)

        for key in drop_keys: aggregate_dict.pop(key, None)

        if len(aggregate_dict.keys()) == 0:
            return 1

        intersection = 0
        union = len(aggregate_dict.keys())
        for value in aggregate_dict.values():
            if 0.0 not in value:
                intersection += 1
        
        return round(intersection/union, 6)

class Utils:

    @classmethod
    def lists_diff_len(cls, list1, list2):
        return len(list(set(list1) - set(list2)) + list(set(list2) - set(list1)))

    @classmethod
    def append_lists_together(cls, list1, list2):
        """This function calculate list1 union list2.
        It will remove duplicate values and sort the list.
        Args:
            list1: Input first list.
            list2: Input second list.
        Returns:
            list: Return unioned list.
        """
        temp_list = list1 + list2
        temp_list = list(dict.fromkeys(temp_list))
        temp_list.sort()
        return temp_list

    @classmethod
    def get_attr_list_from_obj_list(cls, list_obj, field):
        """This module get attribute object from object.
        Args:
            list_obj: Input attribute object.
            field: Attribute want to retrieve.
        Returns:
            list: Return attribute list.
        Example:
            For port in will return [80, 443]
        """
        return [getattr(x, field) for x in list_obj]

    @classmethod
    def get_attr_list_of_list(cls, len_num, in_list):
        """This module create nested list for input key list.
        Args:
            len_num: length of key list.
            in_list: Input attribute object.
        Returns:
            nested list: Return nested list.
        Example:
            for key list [key1, key2] it will create [[key1_percent, key1_hit, ...], [key2_percent, key2_hit, ...]]
        """
        temp_nested_list = []
        for idx in range(0, len_num):
            append_list = []
            for list in in_list:
                append_list.append(list[idx])

            temp_nested_list.append(append_list)

        return temp_nested_list

    @classmethod
    def return_idx_lower_n(cls, in_list, num):
        """This module return list of index that consist value lower than thershold.
        Args:
            in_list: Input nested list.
            num: Input thershold.
        Returns:
            list: Return list of indexes.
        """
        temp_idxs = []

        for idx in range(0, len(in_list)):
            if in_list[idx][0] < num:
                temp_idxs.append(idx)

        return temp_idxs

    @classmethod
    def remove_value_by_index(cls, in_list, num):
        """This will remove values from nested list.
        First get index of values lower than thershold by function (return_idx_lower_n) 
        then remove them from key list and value nested list.
        Args:
            in_list: Input nested list.
            num: Input thershold.
        Returns:
            nested list: Return nested list after remove values lower than thershold.
        """
        out_list = in_list
        list_len = len(in_list[1])
        idxs = cls.return_idx_lower_n(in_list[1], num)

        for idx1 in reversed(idxs):
            del out_list[0][idx1]
            for idx2 in range(1, list_len):
                if idx1 == idx2:
                    del out_list[1][idx2]

        return out_list

    @classmethod
    def port_attr_lists(cls, obj_ip):
        """Get port attributes from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            nested list: Return nested list of key value for input ip.
        """
        port_list = cls.get_attr_list_from_obj_list(obj_ip.port_dist, 'port')
        port_perc_list = cls.get_attr_list_from_obj_list(
            obj_ip.port_dist, 'percent')

        temp_value = []
        temp_value = cls.get_attr_list_of_list(
            len(port_list), [port_perc_list])

        return [port_list, temp_value]

    @classmethod
    def appid_attr_lists(cls, obj_ip):
        """Get appid attributes from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            nested list: Return nested list of key value for input ip.
        ToDo:
            Now just use percent attributes.
            Other attributes can add later.
        """
        appid_list = cls.get_attr_list_from_obj_list(
            obj_ip.appid_dist, 'app_id')
        appid_perc_list = cls.get_attr_list_from_obj_list(
            obj_ip.appid_dist, 'percent')
        appid_traffic_list = cls.get_attr_list_from_obj_list(
            obj_ip.appid_dist, 'traffic')
        # appid_name_list = get_attr_list_from_obj_list(obj_ip.appid_dist, 'app_name')

        temp_value = []
        temp_value = cls.get_attr_list_of_list(
            len(appid_list), [appid_perc_list])

        return [appid_list, temp_value]

    @classmethod
    def domain_attr_lists(cls, obj_ip):
        """Get domain attributes from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            nested list: Return nested list of key value for input ip.
        ToDo:
            Now just use percent attributes.
            Other attributes can add later.
        """
        domain_list = cls.get_attr_list_from_obj_list(
            obj_ip.domain_dist, 'domain')
        domain_perc_list = cls.get_attr_list_from_obj_list(
            obj_ip.domain_dist, 'percent')
        domain_traffic_list = cls.get_attr_list_from_obj_list(
            obj_ip.domain_dist, 'traffic')
        domain_sub_list = cls.get_attr_list_from_obj_list(
            obj_ip.domain_dist, 'sub')

        temp_value = []
        temp_value = cls.get_attr_list_of_list(
            len(domain_list), [domain_perc_list])

        return [domain_list, temp_value]

    @classmethod
    def dns_attr_lists(cls, obj_ip):
        """Get dns attributes from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            nested list: Return nested list of key value for input ip.
        ToDo:
            Now just use percent attributes.
            Other attributes can add later.
        """
        dns_list = cls.get_attr_list_from_obj_list(obj_ip.dns_dist, 'dns')
        dns_perc_list = cls.get_attr_list_from_obj_list(
            obj_ip.dns_dist, 'percent')
        dns_hit_list = cls.get_attr_list_from_obj_list(obj_ip.dns_dist, 'hit')
        dns_sub_list = cls.get_attr_list_from_obj_list(obj_ip.dns_dist, 'sub')

        temp_value = []
        temp_value = cls.get_attr_list_of_list(len(dns_list), [dns_perc_list])

        return [dns_list, temp_value]

    @classmethod
    def size_attr_lists(cls, obj_ip):
        """Get size attributes from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            nested list: Return nested list of key value (protocol,size) for input ip.
        ToDo:
            Now just use percent attributes.
            Other attributes can be added later.
        """
        protocol_list = cls.get_attr_list_from_obj_list(obj_ip.size_dist, 'protocol')
        size_list = cls.get_attr_list_from_obj_list(obj_ip.size_dist, 'size')

        protocol_size_list = [key for key in zip(protocol_list, size_list)]
        percent_list = cls.get_attr_list_from_obj_list(obj_ip.size_dist, 'percent')

        temp_value = []
        temp_value = cls.get_attr_list_of_list(len(protocol_size_list), [percent_list])

        return [protocol_size_list, temp_value]

    @classmethod
    def trafficperhit_attr_lists(cls, obj_ip):
        """Get total traffic and total hit attributes from input IpMeta object
        then return ratio of them.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            number: Return total_traffic per totalhit ratio.
        """
        total_traffic = obj_ip.total_traffic
        hit = obj_ip.totalhit
        return total_traffic / hit

    @classmethod
    def bscbcs_attr_lists(cls, obj_ip):
        """Get totalbsc and totalbcs attributes from input IpMeta object
        then return ratio of them.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            number: Return bsc per bcs ratio.
        """
        totalbsc = obj_ip.totalbsc
        totalbcs = obj_ip.totalbcs
        return totalbsc / totalbcs

    @classmethod
    def asn_attr_lists(cls, obj_ip):
        """Get asn attribute from input IpMeta object.
        Args:
            obj_ip: Input IpMeta object.
        Returns:
            Str: Return asn name.
        """
        asn = obj_ip.asn
        return asn

    @classmethod
    def create_zero_list(cls, in_metric=None):
        """create 0 values for not existence keys.
        Args:
            in_metric: now without args.
        Returns:
            Str: Return asn name.
        ToDo:
            Now this class just work with percent values.
            if other values added it can change to other returned values.
        """
        return [0]
        # if in_metric == 'port_dist':
        #     return [0]
        # elif in_metric == 'domain_dist' or in_metric == 'dns_dist':
        #     return [0, 0, 0]
        # elif in_metric == 'appid_dist':
        #     return [0, 0]

    @classmethod
    def arr_reConstruct(cls, in_list, key_list, metric):
        """It will reshape input attribute list(add zero value for non existence keys by create_zero_list fucntion).
        Args:
            in_list: Input key_value created list. 
            key_list: union list of keys.
            metric: Input metric of distance.
        Returns:
            nested_list: Return new nested_list.
        """
        temp_list = []
        zero_list = cls.create_zero_list(metric)
        for key in key_list:
            if key in in_list[0]:
                index = in_list[0].index(key)
                temp_list.append(in_list[1][index])
            else:
                temp_list.append(zero_list)

        return [key_list, temp_list]

    @classmethod
    def distribution_distance(cls, in_obj_ip1, in_obj_ip2, dist_metric):
        key_value_1, key_value_2 = [], []
        np_1D_array1, np_1D_array2 = [], []
        # Distance for list attibutes
        if dist_metric == 'port_dist':
            key_value_1, key_value_2 = cls.port_attr_lists(
                in_obj_ip1), cls.port_attr_lists(in_obj_ip2)

        if dist_metric == 'appid_dist':
            key_value_1, key_value_2 = cls.appid_attr_lists(
                in_obj_ip1), cls.appid_attr_lists(in_obj_ip2)

        if dist_metric == 'domain_dist':
            key_value_1, key_value_2 = cls.domain_attr_lists(
                in_obj_ip1), cls.domain_attr_lists(in_obj_ip2)

        if dist_metric == 'dns_dist':
            key_value_1, key_value_2 = cls.dns_attr_lists(
                in_obj_ip1), cls.dns_attr_lists(in_obj_ip2)

        if dist_metric == 'size_dist':
            key_value_1, key_value_2 = cls.size_attr_lists(
                in_obj_ip1), cls.size_attr_lists(in_obj_ip2)

        key_value_1[0] = [tmp for tmp in key_value_1[0] if tmp != None]
        key_value_2[0] = [tmp for tmp in key_value_2[0] if tmp != None]
        key_lists = cls.append_lists_together(key_value_1[0], key_value_2[0])

        np_list1 = np.array(cls.arr_reConstruct(
            key_value_1, key_lists, dist_metric), dtype=object)
        np_list2 = np.array(cls.arr_reConstruct(
            key_value_2, key_lists, dist_metric), dtype=object)

        # Handle empty list for distance calculation
        if np_list1[1].size == 0:
            np_1D_array1 = []
        else:
            np_1D_array1 = np.hstack(np_list1[1])

        if np_list2[1].size == 0:
            np_1D_array2 = []
        else:
            np_1D_array2 = np.hstack(np_list2[1])

        if (np.all(np_1D_array2 == 0) and np_1D_array1.size != 0) or (
                np.all(np_1D_array1 == 0) and np_1D_array2.size != 0):
            dist = 1
        else:
            dist = distance.jensenshannon(
                np_1D_array1, np_1D_array2)
        return dist

    @classmethod
    def non_distribution_distance(cls, in_obj_ip1, in_obj_ip2, dist_metric):
        # Distance for other attibutes
        result = 0
        if dist_metric == 'traffichit_dist':
            th1, th2 = cls.trafficperhit_attr_lists(
                in_obj_ip1), cls.trafficperhit_attr_lists(in_obj_ip2)
            # result will be between 0 and 10. divide 10 to normalize between 0 and 1.
            result = abs(mlog(th1, 10) - mlog(th2, 10)) / 10
            return result

        if dist_metric == 'bscbcs_dist':
            bscbcs1, bscbcs2 = cls.bscbcs_attr_lists(
                in_obj_ip1), cls.bscbcs_attr_lists(in_obj_ip2)
            result = abs(0.1142 * mlog(bscbcs1, 2) - 0.1142 * mlog(bscbcs2, 2))

        if dist_metric == 'asn_dist':
            asn1, asn2 = cls.asn_attr_lists(
                in_obj_ip1), cls.asn_attr_lists(in_obj_ip2)
            if asn1 == asn2:
                result = 0
            else:
                result = 1
        return result

    @classmethod
    def calc_distance(cls, obj_ip1, obj_ip2, dist_metric, remove=None):
        """It will calculate distance between 2 input ips.
        Args:
            obj_ip1: first IpMeta object.
            obj_ip2: second IpMeta object.
            dist_metric: Input distance metric.
            remove: If need to remove value lower than thershold add 'rm' args as last one.
        Returns:
            dict: Return number between 0 and 1.
        """
        dist, temp_dist = 0, 0
        all_dist = {}
        ip1, ip2 = obj_ip1.ip, obj_ip2.ip

        # return 0 if both ip is equal
        if ip1 == ip2:
            if dist_metric == 'all':
                return {'port_dist': 0, 'appid_dist': 0, 'domain_dist': 0, 'dns_dist': 0, 'asn_dist': 0, 'all': 0}
            else:
                return dist

        if dist_metric in ['port_dist', 'appid_dist', 'domain_dist', 'dns_dist', 'size_dist']:
            dist = cls.distribution_distance(obj_ip1, obj_ip2, dist_metric)
            return dist

        elif dist_metric in ['traffichit_dist', 'bscbcs_dist', 'asn_dist']:
            dist = cls.non_distribution_distance(obj_ip1, obj_ip2, dist_metric)
            return dist

        elif dist_metric == 'all':
            for metric in ['port_dist', 'appid_dist', 'domain_dist', 'dns_dist', 'asn_dist', 'size_dist']:
                if metric in ['port_dist', 'appid_dist', 'domain_dist', 'dns_dist', 'size_dist']:
                    temp_dist = cls.distribution_distance(
                        obj_ip1, obj_ip2, metric)
                    all_dist[metric] = temp_dist
                elif metric in ['asn_dist']:
                    temp_dist = cls.non_distribution_distance(
                        obj_ip1, obj_ip2, metric)
                    all_dist[metric] = temp_dist

                dist = dist + pow(temp_dist, 2)
            # return sqrt(dist)
            all_dist['all'] = sqrt(dist)
            return all_dist

    @classmethod
    def get_distance(cls, ip1_obj, ip2_obj, dist_metric):
        result_dist = {}

        if dist_metric != 'all':
            result_dist[dist_metric] = cls.calc_distance(
                ip1_obj, ip2_obj, dist_metric)
        else:
            result_dist = cls.calc_distance(
                ip1_obj, ip2_obj, dist_metric)
        try:
            result_dist['ip1'] = ip1_obj.ip
            result_dist['ip2'] = ip2_obj.ip
        except Exception as e:
            logger.error(str(e))

        return result_dist

if __name__ == '__main__':
    from utils.ipmeta.main import produce_ipmeta

    ip_list: List[IpMeta] = produce_ipmeta('2022-01-23', '2022-02-23', ['142.250.180.42', '142.250.185.42'])
    dist = Utils.get_distance(ip_list[0], ip_list[1], 'dns_dist')
