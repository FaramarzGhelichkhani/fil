import datetime
import logging
import multiprocessing
import pickle
from multiprocessing import Pool
import shutil
import psycopg2
from setuptools import glob
from aaj.models import Signature
from aaj.utils.worker import Worker
from aaj.utils.worker import chunking_data
from fil.settings import ATTACK_CORE_NUMBER, DB_HOST, DB_NAME, DB_PASSWORD, DB_USER, PESTE_HOST, PESTE_NAME, PESTE_PASSWORD, PESTE_USER, REDIS_IP_HOURLY_DB, KHORTUM_SPIDER_SAMPLE_SIZE
from hafeze.utils.functions import fetch_input_ipmeta_from_fil
from khortum.models import IP, Payload, Source
from khortum.utils.functions import payloadcheck
from utils.file_handler import load_objects_from_redis, get_memory_usage
from utils.ipmeta.queries import get_insert_query
from utils.utils import dicttoIpMeta, get_last_day, save_sms_data, todict
from django.db.models import Q


logger = logging.getLogger("ip_classification.main")

_, columns = shutil.get_terminal_size()
line = '-' * columns

def fetch_ipmetas_of_labeled_ips(apps, all_labeled_ips):
    payload_ips = {}
    payload_ips_class = {}
    input_source = Source.objects.filter(Q(name='input') | Q(name='spider'))
    for ip in all_labeled_ips:
        payload = ip.payload.payload
        if payload not in payload_ips.keys():
            payload_ips[payload] = []
        payload_ips[payload].append(ip.ip)
        payload_ips_class.setdefault(payload,[]).append(ip)

    payload_ipmetas = {}
    payload_ipmetas_out = {}
    for app in apps:
        payload = app.payload
        if payload not in payload_ips.keys():
            payload_ips[payload] = []
        len_ips = len(payload_ips[payload])
        if len_ips == 0:
            payload_ipmetas[payload] = []
        else:
            payload_ipmetas[payload] = list(filter(lambda x: payloadcheck(pickle.loads(x), app)[0] , list(
                filter(lambda x: x is not None , load_objects_from_redis(keys=payload_ips[payload], db=REDIS_IP_HOURLY_DB)))))
            payload_ipmetas[payload]= [pickle.loads(ip_pickled) for ip_pickled in payload_ipmetas[payload] ]    

        len_ipmetas = len(payload_ipmetas[payload])   
        if len_ipmetas < KHORTUM_SPIDER_SAMPLE_SIZE: 
            ipmetas = sorted(
                list(filter(lambda x: payloadcheck(x, app)[0],  fetch_input_ipmeta_from_fil(payload=payload , offset_hours='336')[:100])), 
                key = lambda x: x.time , reverse=True)
            payload_ipmetas[payload].extend(ipmetas)         
        try:
            cluster = Payload.input_clustering(payload=app, ips=payload_ipmetas[payload])
        except:
            cluster = {0:payload_ipmetas[payload]}
        payload_ipmetas_out[payload]=[]
        while (len(payload_ipmetas_out[payload]) <  KHORTUM_SPIDER_SAMPLE_SIZE and len(payload_ipmetas_out[payload]) <  len(payload_ipmetas[payload])  )  and\
             len(payload_ipmetas[payload]) > 0:
             for clus in cluster.keys():
                try:
                    ipmeta = cluster[clus].pop(0)
                    payload_ipmetas_out[payload].append(ipmeta)
                except:
                    continue
        payload_ipmetas_out[payload] = payload_ipmetas_out[payload][:KHORTUM_SPIDER_SAMPLE_SIZE]        
        logger.info(f"{len(payload_ipmetas_out[payload])} fetched for payload {payload}.\n")

        for ipmeta in payload_ipmetas_out[payload]:
            if payload in payload_ips_class:
                for ip in payload_ips_class[payload]:
                    if ipmeta.ip == ip.ip:
                        ip.attack_counter += 1
                        ip.update_counter += 1
                        ip.save()
            else:
                try:
                    existed_ips = IP.objects.filter(source__in=input_source, ip=ipmeta.ip,payload= app, generator=ipmeta.ip)
                    for existed_ip in existed_ips:
                        existed_ip.attack_counter += 1
                        existed_ip.update_counter += 1
                        if existed_ip.check != IP.APPROVED_CHECK:
                            existed_ip.check = IP.APPROVED_CHECK
                            existed_ip.notes = "APPROVED by output."
                        existed_ip.save()
                except Exception as e:
                    logger.info(e)   
            logger.info(f"{ipmeta.ip} selected for input. payload: {payload}.") 

    logger.debug("end of fetching ipmetas of labeled ips", {"command": "attack"})
    return payload_ipmetas_out

def sampling_ipmeta(apps, all_labeled_ips):
    payload_ipmetas = {}
    for ip in  all_labeled_ips:
        payload = ip.payload
        note_ = ip.note.replace("tzinfo=<UTC>", "")
        dict_ip = eval(note_)
        ipmeta = dicttoIpMeta([dict_ip])[0]   
        payload_ipmetas.setdefault(payload,[]).append(ipmeta)
    
    payload_ipmetas_out = {}
    for payload in apps:
        if payload.payload not in payload_ipmetas:
            payload_ipmetas_out[payload.payload] =[]

    input_source = Source.objects.filter(Q(name='input') | Q(name='spider'))
    for payload in payload_ipmetas.keys():
        len_ipmetas = len(payload_ipmetas[payload])   
        if len_ipmetas < KHORTUM_SPIDER_SAMPLE_SIZE: 
            gte = get_last_day(336)
            old_ip = IP.objects.filter(payload=payload, update_time__gte=gte, check='approved', source__in=input_source).order_by('-update_time')
            old_ipmetas=[]
            for ip in old_ip:
                note_ = ip.note.replace("tzinfo=<UTC>", "")
                dict_ip = eval(note_)
                ipmeta = dicttoIpMeta([dict_ip])[0]   
                old_ipmetas.append(ipmeta)
            
            payload_ipmetas[payload].extend(old_ipmetas)

        cluster = Payload.input_clustering(payload=payload, ips=payload_ipmetas[payload])
        while (len(payload_ipmetas_out[payload.payload]) <  KHORTUM_SPIDER_SAMPLE_SIZE and len(payload_ipmetas_out[payload.payload]) <  len(payload_ipmetas[payload])  )  and\
             len(payload_ipmetas[payload]) > 0:
             for clus in cluster.keys():
                try:
                    ipmeta = cluster[clus].pop(0)
                    payload_ipmetas_out[payload.payload].append(ipmeta)
                except:
                    continue
        payload_ipmetas_out[payload.payload] = payload_ipmetas_out[payload.payload][:KHORTUM_SPIDER_SAMPLE_SIZE]        
        logger.info(f"{len(payload_ipmetas_out[payload.payload])} fetched for payload {payload.payload}.\n")        
    
    return payload_ipmetas_out

def manage(ordered_apps, signatures, all_labeled_ips, all_unlabeled_ips, models=[], insert_date=None, timeframe='hourly'):
    save_sms_data("attack",f"RAM: {get_memory_usage()['used_memory_rss_human']}/{get_memory_usage()['total_system_memory_human']}")
    save_sms_data("attack",f"{line}")
    save_sms_data("attack",f"signature-base:")
    save_sms_data("attack", f'id-input-output')
    

    simiarity_signature = Signature.objects.get(name='Fil-Similarity')  
    app_signatures = {}
    for signature in signatures:
        payload = signature.payload.payload
        app_signatures.setdefault(payload,[]).append(signature)
    for app in ordered_apps:
        payload = app.payload
        if app.similarity:
            app_signatures.setdefault(payload,[]).append(simiarity_signature)
    
    # app_ipmetas = fetch_ipmetas_of_labeled_ips(ordered_apps, all_labeled_ips )
    app_ipmetas = sampling_ipmeta(ordered_apps, all_labeled_ips )
    logger.info(f"ipmetas of labeled ips fetched.", {"command": "attack"})

    output_ips = []
    output_ips_prime = []
    errors = []
    output_ipmeta_approved = []
    logger.info(f"initialization done.", {"command": "attack"})
    logger.info(f"data created with size {len(all_unlabeled_ips)}", {"command": "attack"})
    statistics_model = {}
    for model in models:
        try:
            logger.debug(f"start find ips {model.get_name()['abbreviated']}", {
                "status": "start",
                "command": "attack"
            })
            worker_info = f'({ATTACK_CORE_NUMBER})> {model.get_name()["abbreviated"]}'
            worker = Worker(info=worker_info, app=None, signature=None, app_ipmetas=None, insert_date=insert_date, model=model, timeframe=timeframe)
            output_list, output_list_prime, error_list = worker.predict_ips_multiprocess(all_unlabeled_ips,ATTACK_CORE_NUMBER)
            logger.info(f"{len(output_list)} unique ips found for {model.get_name()['full']}", {
                "model": model.get_name()['full'],
                "ips": len(output_list),
                "status": "finish",
                "command": "attack"
            })
            for index, ipmeta in enumerate(output_list_prime):
                    ip = output_list[index]
                    check, note = payloadcheck(ipmeta, ip.payload)
                    if check:
                        ip.check = IP.APPROVED_CHECK
                        output_ipmeta_approved.append(ipmeta)
                    else:
                        ip.check = IP.BLOCKED_CHECK
                        ip.note= note
            if insert_date is not None:
                send_output_ips(output_list=output_list,app=None, labeler=model, timeframe=timeframe)
                send_output_ipmetas(output_ipmeta_approved, insert_date)
            else:
                output_ips.extend(output_list)
                output_ips_prime.extend(output_ipmeta_approved)
                errors.extend(error_list)
            if len(error_list) > 0:
                return output_ips, output_ips_prime, list(set(errors))
            if len(error_list) > 0:
                return output_ips, output_ips_prime, list(set(errors))
            
            # for sms 
            if not model.get_name()['full'] in statistics_model:
                statistics_model[model.get_name()['full']]= {}
            
            for ipmeta in output_list:
                if ipmeta.payload.payload in  statistics_model[model.get_name()['full']]:
                    statistics_model[model.get_name()['full']][ipmeta.payload.payload].append(ipmeta.ip)
                else:
                    statistics_model[model.get_name()['full']][ipmeta.payload.payload] = [ipmeta.ip]
                             

        except Exception as e:
            logger.exception(str(e), {"command": "attack"})


    output_ipmeta_approved = []
    for app in ordered_apps:
        statistics = set()
        if app.payload not in app_signatures.keys():
            continue
        try:
            i = 0
            for signature in app_signatures[app.payload]:
                logger.debug(f"start find ips {app.name}", {
                    "app_id": app.payload,
                    "application_name": app.name,
                    "signature": signature.name,
                    "status": "start",
                    "command": "attack"
                })
                worker_info = f'({ATTACK_CORE_NUMBER})> {app.name}-{"{:03d}".format(i)}'
                worker = Worker(worker_info, app, signature, app_ipmetas[app.payload], insert_date, timeframe=timeframe)
                output_list, output_list_prime, error_list = worker.find_similar_ips_multiprocess(all_unlabeled_ips,ATTACK_CORE_NUMBER)
                for ip_model in output_list:
                    statistics.add(ip_model.ip)
                logger.info(f"{len(statistics)} unique ips found for {app.name}", {
                    "app_id": app.payload,
                    "application_name": app.name,
                    "signature": signature.name,
                    "ips": len(statistics),
                    "status": "finish",
                    "command": "attack"
                })
                for index, ipmeta in enumerate(output_list_prime):
                    ip = output_list[index]
                    check, note = payloadcheck(ipmeta, ip.payload)
                    if check:
                        ip = output_list[index]
                        ip.check = IP.APPROVED_CHECK
                        ip.note= todict(ipmeta)
                        output_ipmeta_approved.append(ipmeta)
                    else:
                        ip.check = IP.BLOCKED_CHECK
                        ip.note = note

                if insert_date is not None:
                    send_output_ips(output_list, app, signature, timeframe=timeframe)
                    send_output_ipmetas(output_ipmeta_approved, insert_date)
                else:
                    output_ips.extend(output_list)
                    output_ips_prime.extend(output_ipmeta_approved)
                    errors.extend(error_list)
                if len(error_list) > 0:
                    return output_ips, output_ips_prime, list(set(errors))
                i += 1
                if len(error_list) > 0:
                    return output_ips, output_ips_prime, list(set(errors))
        except Exception as e:
            logger.error(str(e), {"command": "attack"})
    # sms message log
        save_sms_data("attack",f'{app.payload}-{"{:02d}".format(len(app_ipmetas[app.payload]))}-{"{:03d}".format(len(statistics))}')

    for model in statistics_model.keys():
        save_sms_data("attack",f"{line}")
        save_sms_data("attack",f"{model}:")
        save_sms_data("attack",f"id-output")
        for payload_id , ip_list in statistics_model[model].items():
            save_sms_data("attack",f'{payload_id}-{"{:02d}".format(len(ip_list))}')

    return output_ips, output_ips_prime, list(set(errors))


def send_output_ips_to_temp(output_list, timeframe='hourly'):
    database = psycopg2.connect(host=PESTE_HOST, database=PESTE_NAME, user=PESTE_USER, password=PESTE_PASSWORD)
    database_cursor = database.cursor()
    source = '_' +  timeframe
        
    for output_ip in output_list:
        if output_ip.check == IP.APPROVED_CHECK:
            query = f"insert into tasfie_pestetip(ip, app_id, insert_time, update_time, source, comment) values (%s,%s," \
                    f"%s,%s,%s,%s);"
            t = (output_ip.ip, output_ip.payload.payload, datetime.datetime.now(), datetime.datetime.now(), ('fil' if not hasattr(output_ip, 'source_') else output_ip.source_) + source ,
                output_ip.generator if not hasattr(output_ip, 'comment') else output_ip.comment)
            database_cursor.execute(database_cursor.mogrify(query, t))
        else:
            continue
    database.commit()


def send_output_ips_to_main(output_list, timeframe='hourly'):
    database = psycopg2.connect(host=PESTE_HOST, database=PESTE_NAME, user=PESTE_USER, password=PESTE_PASSWORD)
    database_cursor = database.cursor()
    source = '_' +  timeframe
        
    for output_ip in output_list:
        if output_ip.check == IP.APPROVED_CHECK:
            query = f"insert into tasfie_pesteip(ip, service, payload, insert_time, update_time, source, comment) values " \
                    f"(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (ip, service, payload, source) DO UPDATE SET update_time = now();"
            t = (output_ip.ip, 0, output_ip.payload.payload, datetime.datetime.now(), datetime.datetime.now(), ('fil' if not hasattr(output_ip, 'source_') else output_ip.source_) + source ,
                output_ip.generator if not hasattr(output_ip, 'comment') else output_ip.comment)
            database_cursor.execute(database_cursor.mogrify(query, t))
        else:
            continue    
    database.commit()

def send_output_ips_to_fil(output_list):
    from django.db import IntegrityError
    for output_ip in output_list:
        try:
            output_ip.save()
        except IntegrityError as e:
            if 'constraint' in str(e).lower():
                exist_ip = IP.objects.get(ip=output_ip.ip,payload= output_ip.payload, source=output_ip.source, generator=output_ip.generator, type=output_ip.type)
                exist_ip.update_time =  datetime.datetime.now()
                exist_ip.update_counter +=1
                exist_ip.check = output_ip.check
                exist_ip.note = output_ip.note
                exist_ip.save()

def send_output_ips(output_list, app, labeler, timeframe):
    send_output_ips_to_fil(output_list)
    if app is None:
        if labeler.sending_temp:
            send_output_ips_to_temp(output_list, timeframe)
        if labeler.sending_main:
            send_output_ips_to_main(output_list, timeframe)
    else:
        if app.sending_temp and labeler.sending_temp:
            send_output_ips_to_temp(output_list, timeframe)
        if app.sending_main and labeler.sending_main:
            send_output_ips_to_main(output_list, timeframe)


def send_output_ipmetas(output_list_prime, insert_date):
    database = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
    database_cursor = database.cursor()
    for ipmeta in output_list_prime:
        try:
            if hasattr(ipmeta, 'is_complete'):
                del ipmeta.is_complete
            st, tu = get_insert_query(ipmeta, {'insert_time': ('%s', insert_date)})
            t = database_cursor.mogrify(st, tu)
            database_cursor.execute(t)
        except Exception as e:
            logger.exception(str(e), {"command": "attack"})
    database.commit()
