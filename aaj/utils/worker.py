import datetime
import logging
import multiprocessing
import pickle
import numpy as np
import joblib
from aaj.utils.distance import Utils
from fil.settings import IS_LCT, MODELS_ADDRESS
from khortum.models import IP, Source, Payload

logger = logging.getLogger("ip_classification.main")
lock = multiprocessing.Lock()


class Worker:

    def __init__(self, info, app, signature, app_ipmetas, insert_date, model=None, threshold = 0.99, timeframe='hourly'):
        self.total_size = -1
        self.info = info
        self.app = app
        self.signature = signature
        self.app_ipmetas = app_ipmetas
        self.output_list = multiprocessing.Manager().list()
        self.output_list_prime = multiprocessing.Manager().list()
        self.comparison = multiprocessing.Manager().Value('i', 0)
        self.last_print = multiprocessing.Manager().Value('i', 0)
        self.insert_date = insert_date
        self.output_source = Source.objects.get(name='output')
        self.error_list = multiprocessing.Manager().list()
        self.similarity_model = joblib.load(MODELS_ADDRESS+'rf_similarity.joblib')
        self.model = model
        self.model_obj  = self.model.load() if model is not None else None
        self.model_version =  self.model.get_version() if model is not None else None
        self.threshold = threshold
        self.timeframe=timeframe

    def find_similar_ips(self, chunk):
        if len(chunk) == 0:
            return
        output_list_temp = []
        output_list_prime_temp = []
        error_list_temp = []
        if self.signature.needs_input:
            labeled_ipmetas = self.app_ipmetas
        else:
            labeled_ipmetas = [None]
        for labeled_ipmeta in labeled_ipmetas:
            for object in chunk:
                unlabeled_ipmeta = pickle.loads(object)
                similarity_name_condition = self.signature.name == 'Fil-Similarity'  
                similarity_condition = similarity_name_condition or self.signature.needs_input
                result = self.exec_sign(self.signature, unlabeled_ipmeta, labeled_ipmeta, similarity_condition )
                if result['result']:
                    if IS_LCT and not labeled_ipmeta is None:
                        distance = Utils.get_distance(unlabeled_ipmeta, labeled_ipmeta, 'all')['all']
                    else:
                        distance = 0
                    type = 'manual-similarity' if similarity_name_condition  else 'manual-signature'
                    type += f'-{self.timeframe}'
                    output_list_temp.append(
                        IP(ip=unlabeled_ipmeta.ip, payload=self.app,
                           generator='0.0.0.0' if labeled_ipmeta is None else labeled_ipmeta.ip,
                           source=self.output_source,
                           insert_time=self.insert_date if self.insert_date is not None else datetime.datetime.now(),
                           distance=distance,
                           check=IP.CHECKING_CHECK,
                           signature=self.signature.id, type=type))
                    output_list_prime_temp.append(unlabeled_ipmeta)

                if 'error' in result.keys():
                    error_list_temp.append(result['error'])
        with lock:
            self.output_list.extend(output_list_temp)
            self.output_list_prime.extend(output_list_prime_temp)
            self.error_list.extend(error_list_temp)
            self.comparison.value += len(chunk)
            print(f'\r> {self.info} progress: {"%.2f" % round(self.comparison.value * 100 / self.total_size, 2)}%    ',
                  end='')
            percent = round(self.comparison.value * 100 / self.total_size, 2)
            percent_str = "%.2f" % percent

            log_message = f" {self.info} progress: {percent_str}"
            if percent - self.last_print.value > 20:
                self.last_print.value = percent // 1

    def find_similar_ips_multiprocess(self, unlabeled_ipmetas, number_of_processors):
        self.total_size = len(unlabeled_ipmetas)
        chunks = chunking_data(
            unlabeled_ipmetas, number_of_processors)
        pool = multiprocessing.Pool(number_of_processors)
        pool.map(func=self.find_similar_ips, iterable=chunks)
        pool.close()
        pool.join()
        output_list = list(self.output_list)
        output_list_prime = list(self.output_list_prime)
        error_list = list(self.error_list)
        return output_list, output_list_prime, error_list

    def predict_ips(self, chunk):
        if len(chunk) == 0:
            return
        error_list_temp = []
        ipmetas =  [pickle.loads(ipbyte) for ipbyte in chunk]
        predictions = self.model.predict(ipmetas,self.threshold, self.model_obj)
        
        payload_values = set(int(x[1]) for x in predictions)
        payload_objects = Payload.objects.filter(payload__in=payload_values)

        payload_cache = {b.payload: b for b in payload_objects}

        output_list_temp = [ 
            IP(ip=x[0].ip, payload=payload_cache.get(int(x[1])),
               generator='0.0.0.0',
               source=self.output_source,
               insert_time=self.insert_date if self.insert_date is not None else datetime.datetime.now(),
               distance=0,
               check=IP.CHECKING_CHECK,
               signature=0, type=f"automatic-{self.model.get_name()['full']}-{self.model_version}-{self.timeframe}")
               for x in predictions
        ]
        
        output_list_prime_temp = [x[0] for x in predictions]
        with lock:
            self.output_list.extend(output_list_temp)
            self.output_list_prime.extend(output_list_prime_temp)
            self.error_list.extend(error_list_temp)
            self.comparison.value += len(chunk)
            print(f'\r> {self.info} progress: {"%.2f" % round(self.comparison.value * 100 / self.total_size, 2)}%', end='')
            percent = round(self.comparison.value * 100 / self.total_size, 2)
            percent_str = "%.2f" % percent

            log_message = f" {self.info} progress: {percent_str}"
            if percent - self.last_print.value > 20:
                self.last_print.value = percent // 1

    def predict_ips_multiprocess(self, unlabeled_ipmetas, number_of_processors):
        self.total_size = len(unlabeled_ipmetas)
        chunks = chunking_data(
            unlabeled_ipmetas, number_of_processors)
        pool = multiprocessing.Pool(number_of_processors)
        pool.map(func=self.predict_ips, iterable=chunks)
        pool.close()
        pool.join()
        output_list = list(self.output_list)
        output_list_prime = list(self.output_list_prime)
        error_list = list(self.error_list)
        return output_list, output_list_prime, error_list
    
    def exec_sign(self,signature, unlabeled_ipmeta, labeled_ipmeta=None,similarity=False):
        local = {'database_item': unlabeled_ipmeta, 'input_item': labeled_ipmeta}
        payload = signature.payload.payload
        
        if similarity:
            similarity_model = self.similarity_model
            local["similarity_model"] = similarity_model
        try:
            exec(signature.script, globals(), local)
            if 'positive' not in local.keys():
                logger.warning(f"signature {signature.script[0:20]} for payload {payload} has no positive variable",
                            {"command": "attack"})

            return {"result": local['positive']}
        except Exception as e:
            error_message = f"Error when running {payload} for ip {unlabeled_ipmeta.ip}: {e.__str__()}"
            logger.error(error_message, {"command": "attack"})
            return {"result": False, "error": error_message}
        


def chunking_data(data, split):
    total_size = len(data)
    p = split
    q = total_size // p
    r = total_size - split * q
    chunks = [data[(q + 1) * i:(q + 1) * (i + 1)] for i in range(r)] + [
        data[(q + 1) * r + q * i:(q + 1) * r + q * (i + 1)] for i in range(p - r)]
    return chunks