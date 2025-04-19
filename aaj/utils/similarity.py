import math
import ipaddress
import numpy as np 

from aaj.utils.distance import Distance
#from utils.ipmeta.main import check_ipmeta_completion

SIMILARITY_DICT = { 'port_percent_similarity': None, 'port_drop_default_value_ratio': None, 'port_percent_weighted_similarity': None,
    'port_traffic_ratio': None, 'port_number_ratio': None, 'port_sub_ratio': None, 'dns_percent_similarity': None,
    'dns_percent_weighted_similarity': None, 'dns_traffic_ratio': None, 'dns_sub_ratio': None, 'dns_drop_default_value_ratio': None,
    'dns_number_ratio': None, 'domain_percent_similarity': None, 'domain_drop_default_value_ratio': None, 
    'domain_percent_weighted_similarity': None, 'domain_traffic_ratio': None, 'domain_sub_ratio': None, 'domain_number_ratio': None,
    'appid_percent_similarity': None, 'appid_drop_default_value_ratio': None, 'appid_percent_weighted_similarity': None,
    'appid_traffic_ratio': None, 'appid_number_ratio': None, 'appid_sub_ratio': None, 'L4_dist_percent_similarity': None,
    'L4_dist_drop_default_value_ratio': None, 'L4_dist_percent_weighted_similarity': None, 'L4_dist_traffic_ratio': None,
    'L4_dist_sub_ratio': None,  'L4_dist_number_ratio': None, 'L7_dist_percent_similarity': None, 
    'L7_dist_drop_default_value_ratio': None, 'L7_dist_percent_weighted_similarity': None, 'L7_dist_traffic_ratio': None,
    'L7_dist_sub_ratio': None, 'L7_dist_number_ratio':None, 'asn': None, 'total_traffic_ratio': None, 'totalbcs_ratio': None,
    'totalbsc_ratio': None, 'bsc_bcs_ratio': None, 'bcs_hit_ratio': None, 'bsc_hit_ratio': None, 'ip_number_ratio': None}


class Similarity:

    @classmethod
    def ip(cls, ipmeta1, ipmeta2, dist_type='ip', dists=[]):

        similarity_dict = {}
        for k, v in SIMILARITY_DICT.items():
            similarity_dict[k] = v

        if dist_type == 'ip':
            if dists == []: dists = ['port', 'dns', 'domain', 'appid', 'L4_dist', 'L7_dist', 'ratio', 'asn']

            for dist in dists:
                if dist in ['port', 'dns', 'domain', 'appid']:
                    feature_dict1 = making_list_v2(ipmeta1, dist)
                    feature_dict2 = making_list_v2(ipmeta2, dist)
                    similarity_dict = cls.dist_feature(feature_dict1, feature_dict2, dist, similarity_dict)
                elif dist in ['L4_dist', 'L7_dist']:
                    L_dist_input, L_dist_output = generate_layer_dist(dist)
                    feature_dict1 = making_list_Layer_dist(generate_L7_L4_dist(ipmeta1.detection_dist, ipmeta1.total_traffic, L_dist_input, L_dist_output))
                    L_dist_input, L_dist_output = generate_layer_dist(dist)
                    feature_dict2 = making_list_Layer_dist(generate_L7_L4_dist(ipmeta2.detection_dist, ipmeta2.total_traffic, L_dist_input, L_dist_output))
                    similarity_dict = cls.dist_feature(feature_dict1, feature_dict2, dist, similarity_dict)
                elif dist in ['ratio']:
                    traffic_dists = ['total_traffic_ratio', 'totalbcs_ratio', 'totalbsc_ratio', 'bsc_bcs_ratio', 'bcs_hit_ratio', 'bsc_hit_ratio', 'ip_number_ratio']
                    similarity_dict = cls.ratio_features(ipmeta1, ipmeta2, traffic_dists, similarity_dict)
                elif dist in ['asn']:
                    similarity_dict['asn'] = 1.0 if ipmeta1.asn == ipmeta2.asn else 0.0
                else: pass
            
            for value in similarity_dict.values():
                if value != 1:
                    return similarity_dict
            raise Exception("IpMeta is not complete!")

        else:            
            feature_dict1 = making_list_v2(ipmeta1, dist_type)
            feature_dict2 = making_list_v2(ipmeta2, dist_type)
            return cls.dist_feature(feature_dict1, feature_dict2, dist_type, similarity_dict)

    @classmethod
    def dist_feature(cls, feature_dict1, feature_dict2, dist_type, similarity_dict):
        if  feature_dict1['key'] == [] and feature_dict2['key'] == []:
            similarity_dict[dist_type+'_percent_similarity'] = 1.0
            similarity_dict[dist_type+'_drop_default_value_ratio'] = 1.0
            similarity_dict[dist_type+'_percent_weighted_similarity'] = 1.0
            similarity_dict[dist_type+'_traffic_ratio'] = 1.0
            similarity_dict[dist_type+'_sub_ratio'] = 1.0 if dist_type in ['dns', 'domain'] else None
            similarity_dict[dist_type+'_number_ratio'] = 1.0
            return similarity_dict
        elif feature_dict1['key'] == [] or feature_dict2['key'] == []:
            similarity_dict[dist_type+'_percent_similarity'] = 0.0
            similarity_dict[dist_type+'_drop_default_value_ratio'] = 0.0
            similarity_dict[dist_type+'_percent_weighted_similarity'] = 0.0
            similarity_dict[dist_type+'_traffic_ratio'] = 0.0
            similarity_dict[dist_type+'_sub_ratio'] = 0.0 if dist_type in ['dns', 'domain'] else None
            similarity_dict[dist_type+'_number_ratio'] = 0.0
            return similarity_dict
        else: pass
        
        attributes = ['percent', 'drop_default_value_ratio', 'weigted_percent', 'traffic', 'sub']
        for attr in attributes:
            tmp_attr = attr if attr != 'drop_default_value_ratio' else 'percent'
            try:
                attr_dict1 = generate_dict_feature(feature_dict1['key'], feature_dict1[tmp_attr])
                attr_dict2 = generate_dict_feature(feature_dict2['key'], feature_dict2[tmp_attr])
                aggregate_dict = aggregate_distribution(attr_dict1, attr_dict2)
            except:
                aggregate_dict = {}
            if attr == 'percent':
                feature_percent_distance = Distance.jensen_shannon(aggregate_dict)   
                feature_percent_similarity = round(1 - feature_percent_distance, 6)
                similarity_dict[dist_type+'_percent_similarity'] = feature_percent_similarity
            elif attr == 'drop_default_value_ratio':
                dd_value_ratio = Distance.drop_default_value_ratio(aggregate_dict, dist_type)
                similarity_dict[dist_type+'_drop_default_value_ratio'] = dd_value_ratio
            elif attr == 'weigted_percent':
                aggregate_dict = generate_weighted_percent_aggregate_dict(feature_dict1, feature_dict2)
                feature_weighted_percent_distance = 2 * Distance.jensen_shannon(aggregate_dict)   
                feature_weighted_percent_similarity = round(1 - feature_weighted_percent_distance, 6)
                similarity_dict[dist_type+'_percent_weighted_similarity'] = feature_weighted_percent_similarity                
            elif attr == 'traffic':
                feature_traffic_ratio = Distance.calculate_ratio(aggregate_dict)
                similarity_dict[dist_type+'_traffic_ratio'] = feature_traffic_ratio
            elif attr == 'sub':
                feature_sub_ratio = Distance.calculate_ratio(aggregate_dict)
                similarity_dict[dist_type+'_sub_ratio'] = feature_sub_ratio
            else: pass

        f1 = feature_dict1['counts']
        f2 = feature_dict2['counts']
        similarity_dict[dist_type+'_number_ratio'] = 0 if max(f1, f2) == 0 else round(min(f1, f2 )/max(f1, f2), 6)

        return similarity_dict

    @classmethod
    def ratio_features(cls, ipmeta1, ipmeta2, traffic_dists, similarity_dict):

        for dist in traffic_dists:
            if dist == 'total_traffic_ratio':
                t1 = ipmeta1.total_traffic
                t2 = ipmeta2.total_traffic
            elif dist == 'totalbcs_ratio':
                t1 = ipmeta1.totalbcs
                t2 = ipmeta2.totalbcs
            elif dist == 'totalbsc_ratio':
                t1 = ipmeta1.totalbsc
                t2 = ipmeta2.totalbsc
            elif dist == 'bsc_bcs_ratio':
                t1 = None if ipmeta1.totalbsc == 0 or ipmeta1.totalbcs == 0 else ipmeta1.totalbsc/ipmeta1.totalbcs
                t2 = None if ipmeta2.totalbsc == 0 or ipmeta2.totalbcs == 0 else ipmeta2.totalbsc/ipmeta2.totalbcs
            elif dist == 'bcs_hit_ratio':
                t1 = None if ipmeta1.totalbcs == 0 or ipmeta1.totalhit == 0 else ipmeta1.totalbcs/ipmeta1.totalhit
                t2 = None if ipmeta2.totalbcs == 0 or ipmeta2.totalhit == 0 else ipmeta2.totalbcs/ipmeta2.totalhit
            elif dist == 'bsc_hit_ratio':
                t1 = None if ipmeta1.totalbsc == 0 or ipmeta1.totalhit == 0 else ipmeta1.totalbsc/ipmeta1.totalhit
                t2 = None if ipmeta2.totalbsc == 0 or ipmeta2.totalhit == 0 else ipmeta2.totalbsc/ipmeta2.totalhit  
            elif dist == 'ip_number_ratio':
                t1 = int(ipaddress.ip_address(ipmeta1.ip))
                t2 = int(ipaddress.ip_address(ipmeta2.ip))
            else:
                print("dist not found")
            
            if t1 is None and t2 is None:
                similarity_dict[dist] = 1.0
            elif t1 is None or t2 is None:
                similarity_dict[dist] = 0.0
            else:
                similarity_dict[dist] = 0.0 if (max(t1, t2) == 0) else round(min(t1, t2)/max(t1, t2), 6)
    
        return similarity_dict


class FastSimilairty:
    
    DICT_FEATURE_LIST = { 'port_percent_similarity': 0, 'port_drop_default_value_ratio': 1, 'port_percent_weighted_similarity': 2,
        'port_traffic_ratio': 3, 'port_number_ratio': 4, 'port_sub_ratio': 5, 'dns_percent_similarity': 6,
        'dns_percent_weighted_similarity': 7, 'dns_traffic_ratio': 8, 'dns_sub_ratio': 9, 'dns_drop_default_value_ratio': 10,
        'dns_number_ratio': 11, 'domain_percent_similarity': 12, 'domain_drop_default_value_ratio': 13, 
        'domain_percent_weighted_similarity': 14, 'domain_traffic_ratio': 15, 'domain_sub_ratio': 16, 'domain_number_ratio': 17,
        'appid_percent_similarity': 18, 'appid_drop_default_value_ratio': 19, 'appid_percent_weighted_similarity': 20,
        'appid_traffic_ratio': 21, 'appid_number_ratio': 22, 'appid_sub_ratio': 23, 'L4_dist_percent_similarity': 24,
        'L4_dist_drop_default_value_ratio': 25, 'L4_dist_percent_weighted_similarity': 26, 'L4_dist_traffic_ratio': 27,
        'L4_dist_sub_ratio': 28,  'L4_dist_number_ratio': 29, 'L7_dist_percent_similarity': 30, 
        'L7_dist_drop_default_value_ratio': 31, 'L7_dist_percent_weighted_similarity': 32, 'L7_dist_traffic_ratio': 33,
        'L7_dist_sub_ratio': 34, 'L7_dist_number_ratio':35, 'asn': 36, 'total_traffic_ratio': 37, 'totalbcs_ratio': 38,
        'totalbsc_ratio': 39, 'bsc_bcs_ratio': 40, 'bcs_hit_ratio': 41, 'bsc_hit_ratio': 42, 'ip_number_ratio': 43}

    DICT_MIN_FEATUER_LIST = {"port_percent_weighted_similarity": 0.0,
                             "port_number_ratio": 0.1,
                             "domain_percent_weighted_similarity": 0.0,
                             "domain_number_ratio": 0.1,
                             "dns_percent_weighted_similarity": 0.0,
                             "appid_percent_weighted_similarity": 0.0}

    @classmethod
    def ip(cls, ipmeta1, ipmeta2, dists=[]):
        
        similarity_dict = {}
        for k, v in SIMILARITY_DICT.items():
            similarity_dict[k] = v
         
        features_dict1 = {}
        features_dict2 = {}

        if dists == []:
            dists = ['port', 'domain', 'dns', 'appid', 'L4_dist', 'L7_dist', 'ratio', 'asn']

        dist_feature = [x for x in dists if x not in ['ratio', 'asn']]    
        attributes = ['percent', 'drop_default_value_ratio', 'traffic', 'sub']

        for dist in dists:
            if dist in ['L4_dist', 'L7_dist']:
                L_dist_input, L_dist_output = generate_layer_dist(dist)
                features_dict1[dist] = making_list_Layer_dist(generate_L7_L4_dist(ipmeta1.detection_dist, ipmeta1.total_traffic, L_dist_input, L_dist_output))
                L_dist_input, L_dist_output = generate_layer_dist(dist)
                features_dict2[dist] = making_list_Layer_dist(generate_L7_L4_dist(ipmeta2.detection_dist, ipmeta2.total_traffic, L_dist_input, L_dist_output))
            elif dist in ['port', 'domain', 'dns', 'appid']:
                features_dict1[dist] = making_list_with_constriant(ipmeta1, dist, limit_percent=0.005, limit_number=5)
                features_dict2[dist] = making_list_with_constriant(ipmeta2, dist, limit_percent=0.005, limit_number=5)
            else: pass
        
        dist_feature = [x for x in dists if x not in ['ratio', 'asn']]
        
        # check min condition
        similarity_dict = cls.generate_fast_detect_vector(features_dict1, features_dict2, dist_feature, similarity_dict)
        if cls.check_minimal_condition(similarity_dict) == False: return (False, None) 

        # complete dist feature (port, dns, domain, appid, l4_dist, l7_dist)
        similarity_dict = cls.dist_features(features_dict1, features_dict2, similarity_dict, dist_feature, attributes)

        # calculate asn
        if 'asn' in dists:
            similarity_dict['asn'] = 1.0 if ipmeta1.asn == ipmeta2.asn else 0.0

        # calculate traffic ratio feature and ip number
        if 'ratio' in dists:
            traffic_dists = ['total_traffic_ratio', 'totalbcs_ratio', 'totalbsc_ratio', 'bsc_bcs_ratio', 'bcs_hit_ratio', 'bsc_hit_ratio', 'ip_number_ratio']
            similarity_dict = Similarity.ratio_features(ipmeta1, ipmeta2, traffic_dists, similarity_dict)

        # if ipmeta is empty raise exception
        for value in similarity_dict.values():
            if value != 1:
                #return True, np.array(list(similarity_dict.values()), dtype='float')
                return True, similarity_dict
        raise Exception("IpMeta is not complete!")
    
    @classmethod
    def check_minimal_condition(cls, similarity_dict):
        for key, value in cls.DICT_MIN_FEATUER_LIST.items():
            if similarity_dict[key] > value:
                pass
            else:
                return False
        return True
  
    @classmethod    
    def generate_fast_detect_vector(cls, features_dict1, features_dict2, dists, similarity_dict):

        for dist in dists:
            if   features_dict1[dist]['key'] == [] and features_dict2[dist]['key'] == []:
                 similarity_dict[dist+'_number_ratio'] = 1.0
                 similarity_dict[dist+'_percent_weighted_similarity'] = 1.0
            elif features_dict1[dist]['key'] == [] or features_dict2[dist]['key'] == []:
                 similarity_dict[dist+'_number_ratio'] = 0.0
                 similarity_dict[dist+'_percent_weighted_similarity'] = 0.0
            else:
                aggregate_dict = generate_weighted_percent_aggregate_dict(features_dict1[dist], features_dict2[dist])
                feature_weighted_percent_distance = 2 * Distance.jensen_shannon(aggregate_dict)
                feature_weighted_percent_similarity = round(1 - feature_weighted_percent_distance, 6)
                #similarity_dict.append(feature_weighted_percent_similarity)
                similarity_dict[dist+'_percent_weighted_similarity'] = feature_weighted_percent_similarity

                f1 = features_dict1[dist]['counts']
                f2 = features_dict2[dist]['counts']
                number_ratio = 0 if max(f1, f2) == 0 else round(min(f1, f2 )/max(f1, f2), 6)
                similarity_dict[dist+'_number_ratio'] = number_ratio  

        return similarity_dict
        
    @classmethod
    def dist_features(cls, features_dict1, features_dict2, similarity_dict, dists, attributes):
        for dist in dists:
            if features_dict1[dist]['key'] == [] and features_dict2[dist]['key'] == []:
                similarity_dict[dist+'_percent_similarity'] = 1.0
                similarity_dict[dist+'_drop_default_value_ratio'] = 1.0
                similarity_dict[dist+'_sub_ratio'] = 1.0 if dist in ['dns', 'domain'] else None
                similarity_dict[dist+'_traffic_ratio'] = 1.0
            elif features_dict1[dist]['key'] == []  or features_dict2[dist]['key'] == []:
    
                similarity_dict[dist+'_percent_similarity'] = 0.0
                similarity_dict[dist+'_drop_default_value_ratio'] = 0.0
                similarity_dict[dist+'_sub_ratio'] = 0.0 if dist in ['dns', 'domain'] else None
                similarity_dict[dist+'_traffic_ratio'] = 0.0
            else: 
                for attr in attributes:
                    tmp_attr = attr if attr != 'drop_default_value_ratio' else 'percent'
                    try:
                        attr_dict1 = generate_dict_feature(features_dict1[dist]['key'], features_dict1[dist][tmp_attr])
                        attr_dict2 = generate_dict_feature(features_dict2[dist]['key'], features_dict2[dist][tmp_attr])
                        aggregate_dict = aggregate_distribution(attr_dict1, attr_dict2)
                    except:
                        aggregate_dict = {}
                    if attr == 'percent':
                        feature_percent_distance = Distance.jensen_shannon(aggregate_dict)   
                        feature_percent_similarity = round(1 - feature_percent_distance, 6)
                        similarity_dict[dist+'_'+attr+'_similarity'] = feature_percent_similarity
                    elif attr == 'drop_default_value_ratio':
                        dd_value_ratio = Distance.drop_default_value_ratio(aggregate_dict, dist)
                        similarity_dict[dist+'_'+attr] = dd_value_ratio
                    elif attr == 'traffic':
                        feature_traffic_ratio = Distance.calculate_ratio(aggregate_dict)
                        similarity_dict[dist+'_'+attr+'_ratio'] = feature_traffic_ratio
                    elif attr == 'sub':
                        feature_sub_ratio = Distance.calculate_ratio(aggregate_dict)
                        similarity_dict[dist+'_'+attr+'_ratio'] = feature_sub_ratio

        return similarity_dict


class DetectPayload:
    def __init__(self, detect_name, detect_labels):
        self.detect_name = detect_name
        self.detect_labels = detect_labels


class LayerDist:
    def __init__(self, percent = 0.0, traffic = 0):
        self.percent = percent
        self.traffic = traffic


class DetectPayload:
    def __init__(self, detect_name, detect_labels):
        self.detect_name = detect_name
        self.detect_labels = detect_labels


class LayerDist:
    def __init__(self, percent = 0.0, traffic = 0):
        self.percent = percent
        self.traffic = traffic


def generate_weighted_percent_aggregate_dict(feature_dict1, feature_dict2):
    p_percent = np.array(feature_dict1['percent'])
    q_percent = np.array(feature_dict2['percent'])
    p_traffic = np.array(feature_dict1['traffic'])
    q_traffic = np.array(feature_dict2['traffic'])
    p_weight = (np.linalg.norm(p_traffic)/(np.linalg.norm(q_traffic)+np.linalg.norm(p_traffic))) * p_percent
    q_weight = (np.linalg.norm(q_traffic)/(np.linalg.norm(q_traffic)+np.linalg.norm(p_traffic))) * q_percent
    
    attr_dict1 = generate_dict_feature(feature_dict1['key'], p_weight)
    attr_dict2 = generate_dict_feature(feature_dict2['key'], q_weight)
    aggregate_dict = aggregate_distribution(attr_dict1, attr_dict2)

    return aggregate_dict


def generate_dict_feature(list_field, list_feature):
    feature_dict = {}

    for i in range(len(list_field)):
        key = list_field[i]
        value = list_feature[i]
        feature_dict[key] = value

    return feature_dict


def weighted_jaccard_similarity(list1, list2, weights1, weights2):
    
    if len(list1) != len(weights1) or len(list2) != len(weights2):
        raise ValueError("Lengths of sets and weights should be the same.")
    set1 = set(list1)
    set2 = set(list2)
    intersection = set1.intersection(set2)
    numerator = sum(min(weights1[list1.index(elem)], weights2[list2.index(elem)]) for elem in intersection)
    
    set1_weights_sum = sum(weights1)
    set2_weights_sum = sum(weights2)
    denominator = set1_weights_sum + set2_weights_sum - numerator
    
    if denominator == 0:
        return 0.0  # To handle the case where both sets are empty
    
    return numerator / denominator


def jaccard(list1, list2):
    intersection = len(list(set(list1).intersection(list2)))
    union = (len(list1) + len(list2)) - intersection
    return float(intersection) / union


def euclidean_similarity(list1, list2,  weights1, weights2, same_key=True , percent=True):
    if max(len(list1),len(list2))  == 0 :
        return 1 
    if len(list1) == 0 or len(list2) == 0:
        return 0
    if same_key:
        set1 = set(list1)
        set2 = set(list2)
        intersection = set1.intersection(set2)
        if len(intersection) == 0:
            return 0
        vector1 = [weights1[list1.index(key)] for key in intersection]
        vector2 = [weights2[list2.index(key)] for key in intersection]
    else:
        if len(list1) > len(list2):
            vector1 = sorted([weights1[list1.index(key)] for key in list1],reverse=True)[:len(list2)]
            vector2 = sorted([weights2[list2.index(key)] for key in list2],reverse=True)[:len(list2)]
        else:
            vector1 = sorted([weights1[list1.index(key)] for key in list1],reverse=True)[:len(list1)]
            vector2 = sorted([weights2[list2.index(key)] for key in list2],reverse=True)[:len(list1)]
            
    if  percent: 
        return 1 - math.sqrt(sum((x - y) ** 2 for x, y in zip(vector1, vector2)))
    else:
        return 1 -  ( (np.linalg.norm(np.array(vector1) - np.array(vector2) )) / 
                        np.linalg.norm(np.ones(len(vector1))*max(vector1+vector2)) ) 
    

def make_tld_lists(doms,percents):
    tld_dict = {}
    for index, dom in  enumerate(doms):
        try:
            root , tld  = dom.split('.')
            if tld in tld_dict:
                tld_dict[tld] += percents[index]
            else:
                tld_dict[tld] = percents[index]
        except:
            continue
    return [list(tld_dict.keys()), list(tld_dict.values())] 


def make_char_count_list(doms):
    char_count = {}
    for word in doms:
        for char in word:
            if char in char_count:
                char_count[char] += 1
            else:
                char_count[char] = 1 
    return [list(char_count.keys()), list(char_count.values())]    


def domain_dns_similarity(p1,p2,dist_type='dns_dist',weight=None):
    if dist_type == 'dns_dist' and weight is None:
        w = [1, 4, 4, 2, 2, 0, 2, 1]
    elif dist_type == 'domain_dist' and weight is None:
        w =  [1, 4, 4, 2, 2, 1, 2, 1]
    elif weight is not None :
        w = weight
    
    if p1==p2:
        return [1, 1, 1, 1, 1, 1, 1, 1], None, 100
    
    dom1 , dom2 = p1[0], p2[0]
    percents1, percents2 = p1[1], p2[1]
    
    dom_count_sim = (min(len(dom1) ,len(dom2)) / max(len(dom1),len(dom2)))
    
    # null domain , aggregated_doamin , tf matrix :
    if 'null-domain' in dom1 and 'null-domain' in dom2:
        null_domain_1_index = dom1.index('null-domain')
        null_domain_2_index = dom2.index('null-domain')
        percent_null_domain = euclidean_similarity( [dom1[null_domain_1_index]] 
        , [dom2[null_domain_2_index]]  , [percents1[null_domain_1_index]],[percents2[null_domain_2_index]])
    
        dom1.remove('null-domain')
        dom2.remove('null-domain')
        percents1.remove(percents1[null_domain_1_index])
        percents2.remove(percents2[null_domain_2_index])
    else:
        percent_null_domain = 0
    
   
    
    dom1 , dom2 = p1[0][:5], p2[0][:5]
    percents1, percents2 = p1[1][:5], p2[1][:5]
    sub1, sub2 = p1[2][:5], p2[2][:5]
    
    domain_key_similarity = jaccard(dom1,dom2)
    doms_percent_similairty = weighted_jaccard_similarity(dom1 , dom2 ,percents1 , percents2  )
    percent_not_key = euclidean_similarity( dom1 , dom2  , percents1,percents2, same_key=False)
    sub_not_key = euclidean_similarity( dom1 , dom2  , sub1,sub2, same_key=False , percent=False)
    
    
  
    
    # tld :
    tld1 , tld_percents1  = make_tld_lists(dom1, percents1)
    tld2 , tld_percents2  = make_tld_lists(dom2, percents2)
    if len(tld1) > 0 and len(tld2) > 0 : 
        tld_percent_similarity= euclidean_similarity(tld1 , tld2 ,tld_percents1 , tld_percents2 ) 
    else:
        tld_percent_similarity = 0
        
    # char dist
    char1 , char_count1 = make_char_count_list(dom1)
    char2 , char_count2 = make_char_count_list(dom2)
    char_similarity = euclidean_similarity( char1 , char2, char_count1, char_count2, percent= False)
    
    
    vector = [dom_count_sim, domain_key_similarity, doms_percent_similairty , percent_not_key , 
     sub_not_key, percent_null_domain , tld_percent_similarity , char_similarity ]
    similarity = np.dot(vector,w)
    similarity_chance = 100 * similarity  / np.dot([1,1,1,1,1,1,1,1],w)
    return vector, similarity,  similarity_chance


def port_app_similarity(p1,p2,dist_type='port_dist',weight=None):
    if dist_type == 'port_dist' and weight is None:
        w = [1, 2, 1, 2]
    elif dist_type == 'appid_dist' and weight is None:
        w = [0.1, 1, 0.5, 0.1]
    elif weight is not None :
        w = weight
        
    ports1 , ports2       = p1[0], p2[0]
    percents1 , percents2 = p1[1][:5], p2[1][:5]
    if max(len(ports1),len(ports2))  == 0 :
        port_count_sim  = 1
        return  None,None , 100   
    else:         
        port_count_sim  = (min(len(ports1) ,len(ports2)) / max(len(ports1),len(ports2)) )
    ports1 , ports2       = p1[0][:5], p2[0][:5]
    
    port_similarity = jaccard(ports1,ports2)
    percent_not_key = euclidean_similarity( ports1 , ports2  , percents1,percents2, same_key=False)
    port_percent_similairty = weighted_jaccard_similarity(ports1 , ports2 ,percents1 , percents2  )

    
    v= np.dot([port_count_sim , port_similarity,percent_not_key,port_percent_similairty],w)
    return (port_count_sim , port_similarity,percent_not_key,port_percent_similairty) , v , 100*v/np.dot([1,1,1,1],w)


def asn_similarity(asn1,asn2):
    if str(asn1) == str(asn2):
        return 100 
    else:
        return 0


def traffic_similarity(traffic1,traffic2):
    sim = 100*euclidean_similarity(['traffic'], ['traffic'], [traffic1],[traffic2], percent=False)
    return sim


def making_list(ipmeta,dist):
    if dist is not None:
        key = []
        percent = []
        sub = []
        dist_ = 'app_id' if dist == 'appid' else dist
        for p in getattr(ipmeta,dist+'_dist'):     
            key.append(getattr(p,dist_) )
            percent.append(p.percent)
            try:
                sub.append(p.sub)
            except:
                continue

        return [key,percent,sub]
    else:
        return ipmeta    


def making_list_v2(ipmeta, feature_type):
    if feature_type is not None:
        extract_feature_dict = {
            'key': [],
            'percent': [],
            'traffic': [],
            'sub': [],
            'counts' : 0,
        }
        
        feature_dists = getattr(ipmeta, feature_type + '_dist')
        feature_type = 'app_id' if feature_type == 'appid' else feature_type
        feature_type = 'site_name' if feature_type == 'site' else feature_type

        for elem in feature_dists:
            if elem.percent == 0.0:
                continue
            extract_feature_dict['key'].append(getattr(elem, feature_type))
            extract_feature_dict['percent'].append(elem.percent)
            # some feature has traffic (ex: domain) # but some feature has hit (ex: dns)
            try:
                #for percent is exist but traffic is None
                if elem.traffic is None: 
                    extract_feature_dict['traffic'].append(elem.percent * ipmeta.total_traffic)
                else:
                    extract_feature_dict['traffic'].append(elem.traffic)
            except:
                extract_feature_dict['traffic'].append(elem.hit)
            # some feature (not All) has sub (ex: domain)
            try:
                extract_feature_dict['sub'].append(elem.sub)
            except:
                pass
        extract_feature_dict['counts'] = len(feature_dists)
        
        return extract_feature_dict
    
    else:
        print("feature_type is Not Exist!!")
        return None


def making_list_with_constriant(ipmeta, feature_type, limit_percent, limit_number):
    if feature_type is not None:
        extract_feature_dict = {
            'key': [],
            'percent': [],
            'traffic': [],
            'sub': [],
            'counts' : 0,
        }
        
        feature_dists = getattr(ipmeta, feature_type + '_dist')
        feature_type = 'app_id' if feature_type == 'appid' else feature_type
        
        extract_feature_dict['counts'] = len(feature_dists)

        tmp_total_percent = 0
        for i, elem in enumerate(feature_dists):
            if elem.percent == 0.0 :
                pass             
            elif elem.percent < limit_percent and i > limit_number:
                percent_total_aggregated_low_percent = 1 - tmp_total_percent
                percent_total_aggregated_low_percent = 1 - tmp_total_percent
                if feature_type == 'dns':
                    remain_hit = 0
                    for j in range(i+1, len(feature_dists)):
                       remain_hit += feature_dists[j].hit
                    traffic_total_aggregated_low_percent = remain_hit
                else:
                    traffic_total_aggregated_low_percent = int(ipmeta.total_traffic * percent_total_aggregated_low_percent)
                #sub_total_aggregated_low_percent = len(feature_dists) - i
                sub_total_aggregated_low_percent = 1
                extract_feature_dict['key'].append('aggregated_low_percent_' + feature_type)
                extract_feature_dict['percent'].append(percent_total_aggregated_low_percent)
                extract_feature_dict['traffic'].append(traffic_total_aggregated_low_percent)
                extract_feature_dict['sub'].append(sub_total_aggregated_low_percent)
                return extract_feature_dict
            else:
                tmp_total_percent += elem.percent
                extract_feature_dict['key'].append(getattr(elem, feature_type))
                extract_feature_dict['percent'].append(elem.percent)
                # some feature has traffic (ex: domain) # but some feature has hit (ex: dns)
                try:
                    #for percent is exist but traffic is None
                    if elem.traffic is None: 
                        extract_feature_dict['traffic'].append(elem.percent * ipmeta.total_traffic)
                    else:
                        extract_feature_dict['traffic'].append(elem.traffic)
                except:
                    extract_feature_dict['traffic'].append(elem.hit)
                # some feature (not All) has sub (ex: domain)
                try:
                    extract_feature_dict['sub'].append(elem.sub)
                except:
                    pass
        
        return extract_feature_dict
    
    else:
        print("feature_type is Not Exist!!")
        return None
    

def ip_similarity(ip1,ip2,w = [1,1,1,0.5,0.1]):
    if asn_similarity(ip1.asn,ip2.asn) == 100:
        port_sim  = port_app_similarity(making_list(ip1,'port'), making_list(ip2,'port'),dist_type = 'port_dist')
        domain_sim= domain_dns_similarity(making_list(ip1,'domain'), making_list(ip2,'domain'), dist_type='domain_dist') 
        dns_sim   = domain_dns_similarity(making_list(ip1,'dns'), making_list(ip2,'dns'), dist_type='dns_dist')
        app_sim   = port_app_similarity(making_list(ip1,'appid'), making_list(ip2,'appid'),dist_type = 'appid_dist')
        traffic_sim= traffic_similarity(ip1.total_traffic, ip2.total_traffic)
        
        sim_vector = [port_sim[2], domain_sim[2], dns_sim[2], app_sim[2], traffic_sim]
        similarity = np.dot(sim_vector,w)
        similarity_chance = 100 * similarity  / np.dot([100,100,100,100,100],w)
        
        return sim_vector,similarity, similarity_chance
    else:
        return [0,0,0,0,0], 0, 0    


def aggregate_distribution(probeblity_dict1, probeblity_dict2):
    
    xPQx_dict={}
    for xd1, Pxd1 in probeblity_dict1.items():
        if xd1 == "" or Pxd1 == "":
            continue
        Pxd2 = probeblity_dict2.get(xd1)
        if Pxd2 is None:
            Pxd2 = 0.0
        xPQx_dict.update({xd1:[Pxd1, Pxd2]})
                    
    for xd2, Pxd2 in probeblity_dict2.items():
        if xd2 == "" or Pxd2 == "":
            continue
        Pxd1 = probeblity_dict1.get(xd2)
        if Pxd1 is None:
            Pxd1 = 0.0
            xPQx_dict.update({xd2:[Pxd1, Pxd2]})
    
    return xPQx_dict


def generate_L7_L4_dist(detection_dist, total_traffic, layer_dist, layer_dist_return):
    total_traffic = 0
    for detection in detection_dist:
        total_traffic += detection.traffic
        sum_traffic = 0
        for key in layer_dist.keys():
            for detect_label in key.detect_labels:
                if detect_label == detection.detection:
                    layer_dist_return[key.detect_name].traffic += detection.traffic
                    sum_traffic += detection.traffic              
    
    sum_value = 0
    for value in layer_dist_return.values():
        sum_value += value.traffic
        
    # if sum_value == 0:
    #     layer_dist_return['others'].percent = 1.0
        
    for key, value in layer_dist_return.items():
        if sum_value != 0:
            layer_dist_return[key].percent = value.traffic/sum_value
    
    return layer_dist_return


def generate_layer_dist(dist):
    if dist == 'L4_dist':
        tcp_labels = ['6s']
        tcp_detect = DetectPayload('tcp', tcp_labels)
        udp_labels = ['17s']
        udp_detect = DetectPayload('udp', udp_labels)
        icmp_labels = ['3501s']
        icmp_detect = DetectPayload('icmp', icmp_labels)

        L_dist_input = {tcp_detect: 0.0, udp_detect: 0.0, icmp_detect: 0.0}
        L_dist_output = {'tcp': LayerDist(), 'udp': LayerDist(), 'icmp': LayerDist(), 'others': LayerDist()}      
    
    elif dist == 'L7_dist':
        ssl_labels = ['1122s', '1122p', '1122m' , '1122c', '1102s', '1102p', '1102m' , '1102c', '1120s', '1120p', '1120m' , '1120c', '847s ', '847p', '847m', '847c', '1111s',  '1111p', '1111m' , '1111c', '1112s', '1112p', '1112m' , '1112c', '1113s', '1113p', '1113m' , '1113c', '1114s', '1114p', '1114m' , '1114c', '1115s', '1115p', '1115m' , '1115c', '1116s', '1116p', '1116m' , '1116c', '1117s', '1117p', '1117m' , '1117c', '1118s', '1118p', '1118m' , '1118c', '1119s', '1119p', '1119m' , '1119c', '1121s', '1121p', '1121m' , '1121c']
        ssl_detect = DetectPayload('ssl', ssl_labels)
        v2ray_labels = ['28490p', '28496p', '28513p', '28514p', '28516p', '28531p', '28532p', '28535p', '28545p', '28551p', '28563p', '28564p', '28595p', '28623p', '28625p', '28642p', '28671p', '28794p', '28797p', '28814p', '28835p']
        v2ray_detect = DetectPayload('v2ray', v2ray_labels)
        http_labels = ['676s', '676p', '676m', '676c', '1001s', '1001p', '1001m', '1001c']
        http_detect = DetectPayload('http', http_labels)
        quic_labels = ['1103s', '1103p', '1103m' , '1103c', '1104s', '1104p', '1104m' , '1104c', '1105s', '1105p', '1105m' , '1105c',]
        quic_detect = DetectPayload('quic', quic_labels)
        dns_labels = ['617s', '617p', '617m', '617c']
        dns_detect = DetectPayload('dns', dns_labels)
        ssh_labels = ['846s']
        ssh_detect = DetectPayload('ssh', ssh_labels)

        L_dist_input = {ssl_detect: 0.0, http_detect: 0.0, v2ray_detect: 0.0, quic_detect: 0.0, dns_detect: 0.0, ssh_detect: 0.0}
        L_dist_output = {'ssl': LayerDist(), 'http': LayerDist(), 'v2ray': LayerDist(), 'quic': LayerDist(), 'dns': LayerDist(), 'ssh': LayerDist(), 'others': LayerDist()}
    
    else:
        L_dist_input = {}
        L_dist_output = {}
    
    return L_dist_input, L_dist_output


def making_list_Layer_dist(ipmeta_layer):
    feature_dict = {'key': [],'percent': [],'traffic': [],'sub': [],'counts' : 0}     
    for key in ipmeta_layer.keys():
        if ipmeta_layer[key].percent != 0.0:
            feature_dict['key'].append(key)
            feature_dict['percent'].append(ipmeta_layer[key].percent)
            feature_dict['traffic'].append(ipmeta_layer[key].traffic)
            feature_dict['counts'] += 1
    
    return feature_dict



