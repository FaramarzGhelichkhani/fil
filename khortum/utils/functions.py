import pickle
import tempfile
import joblib
from aaj.utils.similarity import FastSimilairty
from hafeze.utils.functions import fetch_ipmeta_from_fil
from utils.ipmeta.main import check_ipmeta_completion
from utils.file_handler import get_keys_from_redis, load_objects_from_redis
from autoutils.file import write_file
from fil.settings import MODELS_ADDRESS, REDIS_IP_DAILY_DB, IS_HOURLY
from django.http import FileResponse


def fetch_ipmeta(queryset):
    ipmetas = []      

    if len(queryset) > 10:
        raise ValueError("too many ips.select less than 10. ")
    
    ipmetas = fetch_ipmeta_from_fil(queryset)
    if len(ipmetas) == 0:
        raise ValueError("No Metadata for inputs. ")

    return ipmetas 

def apply_similarity_on_ip(ipmetas,dist_type=None,databas_ips=None):
    
    if  databas_ips is None:
        keys = get_keys_from_redis(REDIS_IP_DAILY_DB)
        all_unlabeled = load_objects_from_redis(keys, REDIS_IP_DAILY_DB)
        all_unlabeled = [pickle.loads(ipmeta) for ipmeta in all_unlabeled]
    else :
        all_unlabeled = databas_ips    
    
    result = []
    simlilarity_model  = joblib.load(MODELS_ADDRESS+'rf_similarity.joblib')
    error = ""
    for input_ip in  ipmetas:
        try:
            if not check_ipmeta_completion(input_ip,dist_type):
                raise ValueError(f"{input_ip.ip} has not {dist_type} Metadata in database.\n")
            for ip in all_unlabeled:
                if not check_ipmeta_completion(ip,dist_type):
                    continue
                try:
                    min_condition, similarity_vector =  FastSimilairty.ip(input_ip, ip)
                    if min_condition:
                        if simlilarity_model.predict(similarity_vector.reshape(1,-1))[0] == 1:
                            result.append((input_ip,ip))
                except:
                    continue            
        except ValueError as e:
            error += str(e) 
            continue

    if len(error) > 0:
        raise ValueError(error)
            
    return result

def download_file_response(file_data, filename):
    """
        Download file response
    """
    with tempfile.NamedTemporaryFile(suffix=".txt") as temp_file:
        write_file(temp_file.name, file_data)
        return FileResponse(open(temp_file.name, 'rb'), filename=filename)

def payloadcheck(ipmeta,payload):
    check = True
    note  = ''
    
    if ipmeta.total_traffic < payload.min_traffic_1GB * 10**9:
        check = False
        note += f'blocked by minimum traffic. {ipmeta.total_traffic}.\n'
    
    if payload.dns_block_list == ['anydns'] and ipmeta.dns_dist != []:
        check = False
        note += 'blocked because it has dns.\n'
    
    elif  payload.dns_block_list != ['anydns']:
        for dnsdist in ipmeta.dns_dist:
            if dnsdist.dns in payload.dns_block_list:
                check = False
                note += f'blocked by dns check, {dnsdist.dns}.\n'

    if ipmeta.asn in payload.asn_block_list:
        check = False
        note += f'blocked by asn check, {ipmeta.asn}.\n'

    if IS_HOURLY:
        for detection in ipmeta.detection_dist:
            if detection.detection in payload.detection_block_list:
                check = False
                note += f'blocked by detection check, {detection.detection}.\n'
    else:
        for appdist in ipmeta.appid_dist:
            if appdist.app_id in payload.appid_block_list:
                check = False
                note += f'blocked by appid check, {appdist.app_id}.\n'

    return check, note
