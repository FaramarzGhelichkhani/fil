import json
import logging
import pickle
import datetime
from aaj.models import Signature
from aaj.utils.manager import send_output_ipmetas, send_output_ips_to_fil, send_output_ips_to_main, send_output_ips_to_temp
from aaj.utils.worker import Worker
from hafeze.utils.functions import fetch_ipmeta_from_fil
from khortum.models import IP, Payload, Source
from khortum.utils.functions import payloadcheck
from utils.ipmeta.main import ipmeta_aggregator, produce_ipmeta_clickhouse
from utils.utils import get_last_day, todict
from kafka import KafkaConsumer, KafkaProducer
from utils.file_handler import load_objects_from_redis
from fil.settings import KAFKA_CONFIG, REDIS_IP_HOURLY_DB
from hafeze.models import ResultCheck
from aaj.utils.detection import Multiprocessing

logger = logging.getLogger("ip_classification.main")


class KafkaQueueHandler:
    
    def __init__(self, database_ipmeta):
        self.input_topic = KAFKA_CONFIG['input_topic']
        self.attack_topic = KAFKA_CONFIG['input_attack_topic'] 
        self.check_topic = KAFKA_CONFIG['check_topic'] 
        self.input_consumer  = KafkaConsumer(self.input_topic,  **KAFKA_CONFIG["Consumer CONFIG"])
        self.attack_consumer = KafkaConsumer(self.attack_topic, **KAFKA_CONFIG["Consumer CONFIG"])
        self.check_consumer = KafkaConsumer(self.check_topic, **KAFKA_CONFIG["Consumer CONFIG"])
        self.producer = KafkaProducer(**KAFKA_CONFIG["Produce CONFIG"])
        self.database_ipmeta = database_ipmeta
    

    def process_input_messegaes(self, message):
        decoded_value = message.value.decode('utf-8')
        message_dict = json.loads(decoded_value)
        ip = message_dict["ip"]
        appid = message_dict["app_id"]
        spider_source = Source.objects.get(name='spider')
        payload  = Payload.objects.get(payload = appid)
        if not payload.generating:
            raise ValueError(f"generating is False for payload {payload.payload}.")
        
        ip_instance, created  = IP.objects.get_or_create(ip=ip,payload=payload, source=spider_source,defaults={'generator':ip, 'type':'Kafka-input'})
        
        if not created:
            ip_instance.update_counter +=1 
            ip_instance.update_time  =  datetime.datetime.now()
            ip_instance.save()

        ipmeta_pickeled = load_objects_from_redis(keys=[ip_instance.ip],db=REDIS_IP_HOURLY_DB)
        ipmeta = None
        if ipmeta_pickeled !=[]:    
            ipmeta = pickle.loads(ipmeta_pickeled[0])
        else:
            gte = get_last_day(23)
            lt  = get_last_day(0)
            ipmetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ip_instance.ip])
            if ipmetas==[]:
                ipmetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ip_instance.ip], timeframe='Minutly')
            ipmeta = ipmeta_aggregator(ipmetas=ipmetas)[0]

        if ipmeta is not None:
            check, note = payloadcheck(ipmeta,payload)
            if check:
                ip_instance.check = IP.APPROVED_CHECK
                ip_instance.note= str(todict(ipmeta))
                send_output_ipmetas([ipmeta], ip_instance.update_time)
                # if payload.similarity:
                #     data = {'payload': payload.payload , 'ipmeta':ipmeta.ip,'insert_time':str(ip_instance.update_time)}
                #     self.producer.send(self.attack_topic, value=json.dumps(data).encode('utf-8'))
                #     self.producer.flush()
                #     ip_instance.attack_counter += 1
                #     logger.info(f"{ip_instance.ip} inserted to attack topic and saved.")
            else:
                if ip_instance.check!= IP.APPROVED_CHECK: 
                    ip_instance.check = IP.BLOCKED_CHECK
                    ip_instance.note = note


        ip_instance.save()
        logger.info(f"{ip_instance.ip} checked and inserted to fildb")
        
    def process_attackips_messeages(self, message):
        "first version one by one attack "
        decoded_value = message.value.decode('utf-8')
        message_dict = json.loads(decoded_value)
        appid = message_dict["payload"]
        ip = message_dict["ipmeta"]
        insert_time = message_dict["insert_time"]
        spider_source = Source.objects.get(name='spider')
        payload  = Payload.objects.get(payload = appid)
        
        if not payload.similarity:
            raise ValueError("payload  has not similarity attribute.")

        input_ip = IP.objects.get(ip=ip, payload=payload, source=spider_source, update_time=insert_time, type='Kafka-input')
        input_ip.insert_time = input_ip.update_time # to fetch based on update_time  not  insert_time
        input_ipmeta = sorted(fetch_ipmeta_from_fil(ips=[input_ip]), key=lambda x: x.time, reverse=True)[0] # out puts are ipmeta of payload  during a day. it could be more than one row.
        similarity_signature = Signature.objects.get(name='Fil-Similarity')
        worker = Worker(payload.name,app= payload, signature=similarity_signature, app_ipmetas= [input_ipmeta], insert_date=None)
        logger.info(f" {input_ipmeta.ip} start to attak.")
        output_list, output_list_prime, error_list = worker.find_similar_ips_multiprocess(self.database_ipmeta,number_of_processors=10)  
        result_ip   = []
        result_ipmeta = []
        for index, ipmeta in enumerate(output_list_prime):
            check, note =payloadcheck(ipmeta=ipmeta, payload=payload)
            if check :
                if payload.similarity_asn_condition:
                    if ipmeta.asn == input_ipmeta.asn:
                        output_list[index].check = IP.APPROVED_CHECK
                        result_ip.append(output_list[index])
                        result_ipmeta.append(ipmeta)
                    else:
                        output_list[index].check = IP.BLOCKED_CHECK
                        output_list[index].note = "blocked by asn condition."
                else:
                    output_list[index].check = IP.APPROVED_CHECK
                    result_ip.append(output_list[index])
                    result_ipmeta.append(ipmeta)
            else:
                output_list[index].check = IP.BLOCKED_CHECK
                output_list[index].note = note

        
        send_output_ips_to_fil(output_list)
        logger.info(f"result  inserted to fildb  for {input_ipmeta.ip} .")
        send_output_ipmetas(result_ipmeta, get_last_day(0))
        logger.info(f"result  inserted to ipmeta  for {input_ipmeta.ip} .")
        
        if payload.sending_temp:
            send_output_ips_to_temp(result_ip)
            logger.info(f"{len(result_ip)} inserted to PESTE TMP  for {input_ipmeta.ip}")
        if payload.sending_main:
            send_output_ips_to_main(result_ip)
            logger.info(f" {len(result_ip)} inserted to PESTE Main  for {input_ipmeta.ip}")

    def process_check_messegaes(self, message):
        decoded_value = message.value.decode('utf-8')
        message_dict = json.loads(decoded_value)
        app_id = message_dict["app_id"]
        ip = message_dict["ip"]
        insert_time = message_dict["insert_time"]
        insert_time_field = datetime.datetime.strptime(insert_time, "%Y-%m-%d %H:%M:%S")

        source_name = message_dict["source"]
        source = Source.objects.get(name=source_name)
        payload  = Payload.objects.get(payload = app_id)
        ipcheck, created = ResultCheck.objects.get_or_create(ip=ip,payload=payload, source=source,defaults={'insert_time':insert_time_field,'payload_check_result':None, 'signature_check_result':None})

        logger.info(f" start to checking for {ipcheck.ip}.")

        if not created:
            if ipcheck.payload_check_result:
                ipcheck.save()
                raise ValueError(f"no need to more check for {ipcheck.ip}.")

        ipcheck.insert_time = insert_time_field
        ipmetas = None 
        lt  = insert_time

        if ipmetas is None or ipmetas == []:
            ten_days_interval = insert_time_field - datetime.timedelta(days=10)
            gte = ten_days_interval.strftime("%Y-%m-%d")
            ipmetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ipcheck.ip],timeframe='Daily')    #fetch daily ipmeta from insert_time to 10 days past. 
        
        if ipmetas is None or ipmetas == []:
            one_days_interval = insert_time_field - datetime.timedelta(hours=10)  
            gte = one_days_interval.strftime("%Y-%m-%d %H:00:00")
            ipmetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ipcheck.ip],timeframe='hourly') #fetch hourly ipmeta from insert_time to 10 hours past.

        # if ipmetas is None or ipmetas == []:
        #     one_hours_interval = insert_time_field - datetime.timedelta(minutes=51) 
        #     gte = one_hours_interval.strftime("%Y-%m-%d %H:%M:00")
        #     ipmetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ipcheck.ip],timeframe='Minutly')   #fetch hourly ipmeta from insert_time to 10 five minute buckets.
        
        if ipmetas is None or ipmetas == []:
            ipcheck.payload_check_result = None
            ipcheck.signature_check_result = None
            ipcheck.ml_check_result = None
            note += 'no meta data.\n' 
            ipcheck.save()
            raise ValueError(f"no meta data found for {ipcheck.ip} .")
        
        # aggregate ipmeta
        if len(ipmetas) != 1: 
            agg_ipmeta = ipmeta_aggregator(ipmetas=ipmetas)
            if len(agg_ipmeta) > 1 :
                raise ValueError("error in ip aggregation.")
        else:
            agg_ipmeta = ipmetas 
        
        ipmeta = agg_ipmeta[0]    
        payload_check_result , payload_note = payloadcheck(ipmeta=ipmeta, payload=payload)
        signatures = Signature.objects.filter(payload=payload, generating=True)
        sign_result= '' 
        sign_note = ''
        if len(signatures) > 0:
            for sign in signatures:
                # worker = Worker("signature check",signature=sign,app=payload, app_ipmetas=None,insert_date=None)
                # sign_result = worker.exec_sign(signature=sign,unlabeled_ipmeta=ipmeta)["result"]
                sign_result = Multiprocessing.exec_sign(signature=sign, signature_input={"database_item": ipmeta})
                if sign_result is False:
                    sign_note = f'blocked by signatuers: {sign.name}'    
        
        ipcheck.payload_check_result = payload_check_result
        ipcheck.signature_check_result = sign_result
        
        ipcheck.note = payload_note   
        ipcheck.note += sign_note   
        ipcheck.note += '\n'
        ipcheck.save()
        logger.info(f"{ipcheck.ip} checked and result saved in db.")

    def read_input_messeges(self):
        for messege in self.input_consumer:
            try:
                self.process_input_messegaes(message=messege)
            except  Exception as e:
                logger.info(f"warning: {e}.")
            self.input_consumer.commit()   

    def read_attack_messeges(self):
        for messege in self.attack_consumer:
            try:
                self.process_attackips_messeages(message=messege) 
            except Exception as e:
                logger.info(f"warning: {e}.")
            self.attack_consumer.commit()
            
    def read_check_messeges(self):
        for messege in self.check_consumer:
            try:
                self.process_check_messegaes(message=messege) 
            except Exception as e:
                logger.info(f"warning: {e}.")
            self.check_consumer.commit()
