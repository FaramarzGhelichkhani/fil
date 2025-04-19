import logging
import datetime
import pickle
import joblib
import numpy as np
from khortum.models import IP, Payload, Source
from aaj.models import IntelligentModel
from django.db import IntegrityError
from multiprocessing import Pool
from khortum.utils.functions import payloadcheck
from utils.utils import get_last_day, send_output_to_peste, todict
from fil.settings import  KHORTUM_SPIDER_SAMPLE_SIZE, ATTACK_CORE_NUMBER
from django.db.models import Q
from mlflow.pyfunc import PyFuncModel
from aaj.utils.similarity import FastSimilairty

logger = logging.getLogger("ip_classification.main")

class Detection:
    def __init__(self, payloads, dataset=None, timeframe='5min'):
        self.payloads = payloads
        self.dataset = dataset
        self.timeframe = timeframe
    
    def base_algorithm_attack(self):
        self.initiate()
        self.apply_signatures_for_all_payloads()
        self.apply_similarity_for_payloads()
        if self.timeframe != '5min':
            self.apply_models_for_all_payloads()
        self.send_output_ips_to_fil()
    
    @classmethod
    def sampling_input_ips(cls, payloads, update_attack_counter=False):
        """
        output:
            list of sampling ip instance 
            return dict : key payload values list of ips.
        """
        result= {}
        gte = get_last_day(336, timeframe='hourly')
        input_sources = ['input', 'spider']    
        for payload in payloads:
            result[payload.payload] =[]
            ips = IP.objects.filter(payload=payload, update_time__gte=gte, check='approved', source__name__in=input_sources).order_by('-update_time', 'attack_counter')
            ips_dict = {ip.ip: ip for ip in ips}
            ipmetas = [ip.get_ipmeta() for ip in ips if ip.note is not None ][:20]
            cluster = Payload.input_clustering(payload=payload, ips=ipmetas)
            
            while len(result[payload.payload]) < KHORTUM_SPIDER_SAMPLE_SIZE and \
                     all(len(iplist) > 0 for iplist in cluster.values()):
                for clus in cluster.keys():
                    try:
                        ipmeta = cluster[clus].pop(0)
                        ip = ips_dict[ipmeta.ip]
                        result[payload.payload].append(ip)
                        if update_attack_counter:
                            ip.attack_counter +=1
                            ip.save()
                    except:
                        continue
        return result

    @classmethod
    def apply_model(cls, model, dataset, input_data=[], func_name='calculate_similarity',processor_number=ATTACK_CORE_NUMBER ):
        """"
        apply intiligent model on dataset
        dataset is list of ipmmetas
        input data  is ipmetas[]
        return output
        """
        multi_process = True
        if not isinstance(model, PyFuncModel):
            if isinstance(model, IntelligentModel):
                if model.name in ("XGBModel_Binary"):
                    multi_process=False
                
                model = model.load_ml_model_obj()
        #    else:
        #        error = "model is not initiligent nor mlflow  object!!!"
        #        logger.error(error)
        #       raise ValueError(error)
        
        fn = func_name if func_name == 'calculate_similarity' else 'binary_model_predict' 
        if multi_process:
            res = Multiprocessing.base_calalculate_parallel(model_or_sign=model, dataset=dataset, func_name=fn, \
                input_ipmetas=input_data,  processor_number=processor_number)
        else:
            ipmetas_flat = []
            ipmetas_list =  Multiprocessing.base_calalculate_parallel(model_or_sign=None, dataset=dataset, func_name='load_objects_process')
            for ipmetas in ipmetas_list:
                ipmetas_flat.extend(ipmetas)
            return Multiprocessing.binary_model_predict_single_process(model=model, dataset=ipmetas_flat)
    
        result = []
        for data in res:
            result.extend(data)
        return result    
    
    @classmethod
    def apply_signature(cls, signature, dataset, input_data=[], processor_number=ATTACK_CORE_NUMBER):
        """"
        apply sign on dataset
        return output
        """
        res = Multiprocessing.base_calalculate_parallel(model_or_sign=signature, dataset=dataset, func_name='execute_sign',\
             input_ipmetas=input_data, processor_number=processor_number)
        result = []
        for data in res:
            result.extend(data)
        return result  

    def initiate(self):
        """
        inititiate lists and variables
        """
        self.input_ips = self.__class__.sampling_input_ips(self.payloads, update_attack_counter=True)
        self.similarity_model = IntelligentModel.objects.get(name="RandomForestSimilarity")
        # self.similarity_ml_obj = self.similarity_model.load_ml_model_obj()
        self.similarity_ml_obj = joblib.load("/var/fil/data/models/rf_similarity.joblib")
        self.output_source = Source.objects.get(name='output')
        self.output_list = []

    def apply_similarity_for_payloads(self):
        for payload in self.payloads:
            input_ipmetas = [ip.get_ipmeta() for ip in self.input_ips[payload.payload]]
            if payload.similarity and len(input_ipmetas) > 0:
                type = self.similarity_model.acronym 
                output = self.__class__.apply_model(model=self.similarity_ml_obj,dataset=self.dataset,input_data=input_ipmetas)
                out = self.append_instance(data=output, payload=payload, type=type)
                logger.info(f"number of outputs for {payload.payload} genereated by {type} is {len(out)}.")
                if self.similarity_model.sending_temp and payload.sending_temp:
                    send_output_to_peste(data=out, source=self.timeframe, main=False)
                if self.similarity_model.sending_main and payload.sending_main:
                    send_output_to_peste(data=out, source=self.timeframe, main=True)
        
    def apply_models_for_all_payloads(self):        
        for payload in self.payloads:
            for model in payload.intelligent_models.filter(generating=True):
                type = model.acronym 
                output = self.__class__.apply_model(model=model,dataset=self.dataset,input_data=[], func_name='binary model')
                out = self.append_instance(data=output, payload=payload, type=type)
                logger.info(f"number of outputs for {payload.payload} genereated by {type} is {len(out)}.")
                if model.sending_temp:
                    send_output_to_peste(data=out, source=self.timeframe, main=False)
                if model.sending_main:
                    send_output_to_peste(data=out, source=self.timeframe, main=True)

    def apply_signatures_for_all_payloads(self): 
        input_ipmetas =[]       
        for payload in self.payloads:
            for sign in payload.signatures.filter(generating=True):
                type = 'signatur'
                if sign.needs_input:
                    input_ipmetas = [ip.get_ipmeta() for ip in self.input_ips[payload.payload]]
                output = self.__class__.apply_signature(signature=sign,dataset=self.dataset,input_data=input_ipmetas)
                out = self.append_instance(data=output, payload=payload, type=type, signature_id=sign.id)
                logger.info(f"number of outputs for {payload.payload} genereated by {sign.name}(signatur) is {len(out)}.")
                if sign.sending_temp:
                    send_output_to_peste(data=out, source=self.timeframe, main=False)
                if sign.sending_main:
                    send_output_to_peste(data=out, source=self.timeframe, main=True)  

    @classmethod
    def check_ips(cls, ips):
        for ip in ips:
            if ip.check == IP.CHECKING_CHECK:
                ipmeta = ip.get_ipmeta()
                check, note = payloadcheck(ipmeta, ip.payload)
                if check:
                    ip.check = IP.APPROVED_CHECK
                else:
                    ip.check = IP.BLOCKED_CHECK
                    ip.note  =  note
        return ips

    def append_instance(self, data, payload, type, signature_id =None):
        """
        data = (ipmeta_detected, ipmeta_generetor, distance)
        """
        out= []
        insert_date = get_last_day(0,timeframe='Minutly')
        for row in data:
            ipmeta = row[0]
            generator = row[1]
            distance = row[2]
            ip_obj =  IP(ip=ipmeta.ip, payload=payload,
                            generator= generator.ip,
                            source=self.output_source,
                            insert_time=insert_date,
                            distance=distance,
                            check=IP.CHECKING_CHECK,
                            signature=signature_id, type=type + f'-{self.timeframe}',
                            note=str(todict(ipmeta)))
            
            if payload.similarity_asn_condition and signature_id == None and generator.ip != '0.0.0.0':
                if ipmeta.asn != generator.asn:
                    ip_obj.check = IP.BLOCKED_CHECK
                    ip_obj.note  = 'blocked  by asn confilict between input and ip'

            out.append(ip_obj)
        
        out = self.__class__.check_ips(ips=out)
        self.output_list.extend(out)
        return out

    def send_output_ips_to_fil(self):
        """"
        send output ip instance to fildb 
        """
        for output_ip in self.output_list:
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
    
class Multiprocessing:
    
    @classmethod
    def base_calalculate_parallel(cls, model_or_sign, dataset, func_name,input_ipmetas=[], processor_number=ATTACK_CORE_NUMBER):
        """"
        model is  ml model_obj 
        dataset: is list of unlabeled ipmeta
        input_ipmeta is list of input ipmeta for each payload. 
        """
        chunk_size = len(dataset) // processor_number        
        chunks = cls.chunking_data(dataset, chunk_size)
        cls.model = model_or_sign
        cls.input_ipmetas = input_ipmetas
        pool_func = getattr(cls, func_name)
        with Pool(processor_number) as p:
            res = p.map(func=pool_func, iterable=chunks)
        return res
    
    @classmethod
    def binary_model_predict_single_process(cls, model, dataset):
        result = []
        predictions = model.predict({"ipmetas":dataset})
        for index, ipmeta in enumerate(dataset):
            if predictions[index] == 1:
                row = (ipmeta, IP(ip='0.0.0.0'), 0)
                result.append(row)
        
        dataset.clear()
        return result
    
    @classmethod
    def binary_model_predict(cls, chunk):
        result = []
        chunk = [pickle.loads(obj) for obj in chunk]
        predictions = cls.model.predict({"ipmetas":chunk})        
        for index, ipmeta in enumerate(chunk):
            if predictions[index] == 1:
                row = (ipmeta, IP(ip='0.0.0.0'), 0)
                result.append(row)
        chunk.clear()
        return result
    
    @classmethod
    def calculate_similarity(cls, chunk):
        result = []        
        for obj in chunk:
            ipmeta1 = pickle.loads(obj)            
            for ipmeta2 in cls.input_ipmetas:
                # sim = cls.model.predict({'ipmeta1': ipmeta1, 'ipmeta2': ipmeta2, 'prob_flag': True, 'fast': True})
                # if sim > 0.5:
                sim = FastSimilairty.ip(ipmeta1,ipmeta2)[1]
                if sim is not None:
                    vector = np.array([sim[key] for key in cls.model.feature_names])
                    pred = cls.model.predict_proba(vector.reshape(1, -1)).tolist()[0][1]  
                    if pred > 0.5 :
                        row = (ipmeta1, ipmeta2, 1.0-pred)
                        result.append(row)
        return result

    @classmethod
    def execute_sign(cls, chunk):
        result = []
        signature = cls.model 
        if signature.needs_input:
            labeled_ipmetas = cls.input_ipmetas 
        else:
            labeled_ipmetas = [None]
        for input_ip in labeled_ipmetas:
            for  obj in chunk:
                database_ip = pickle.loads(obj)
                if cls.exec_sign(signature, {'database_item': database_ip, 'input_item': input_ip}):
                    row = (database_ip, input_ip if input_ip is not None else IP(ip='0.0.0.0'),0)
                    result.append(row)
        chunk.clear()
        return result 

    @classmethod
    def exec_sign(cls,signature, signature_input):
        """""
        execute a python signautre
        input: 
            signature_input = {'database_item': unlabeled_ipmeta, 'input_item': labeled_ipmeta } or any maping for arguments.
        """
        local = signature_input
        try:
            exec(signature.script, globals(), local)
            if 'positive' not in local.keys():
                logger.warning(f"signature {signature.script[0:20]} for payload {signature.payload.payload} has no positive variable",
                            {"command": "attack"})
            return local['positive']
        except Exception as e:
            error_message = f"Error when running {signature.script[0:20]} for ip {local['database_item'].ip} and {local['input_item'].ip}: {e.__str__()}"
            logger.error(error_message, {"command": "attack"})
            return False
    
    @classmethod
    def chunking_data(cls, data, spilit):
        total_size = len(data)
        p = spilit
        q = total_size // p
        r = total_size - spilit * q
        chunks = [data[(q + 1) * i:(q + 1) * (i + 1)] for i in range(r)] + [
            data[(q + 1) * r + q * i:(q + 1) * r + q * (i + 1)] for i in range(p - r)]
        return chunks          

    @classmethod
    def load_objects_process(cls, chunk):
        out = [pickle.loads(obj) for obj in chunk]
        chunk.clear()
        return out
    