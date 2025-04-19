import logging
import pickle
from django.core.management.base import BaseCommand
from aaj.utils.detection import Detection
from fil.settings import REDIS_IP_HOURLY_DB, REDIS_IP_DAILY_DB, REMEMBER_NUMBER_OF_PROCESSOR
from khortum.models import Payload
from utils.file_handler import load_objects_from_redis, get_keys_from_redis
from utils.utils import get_last_day
from utils.ipmeta.main import produce_ipmeta_clickhouse

logger = logging.getLogger("ip_classification")

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('-t','--timeframe', default='5min', type=str)
        parser.add_argument('-gte','--gte', default=13, type=int)
        parser.add_argument('-lt','--lt',   default=10, type=int)

    def handle(self, *args, **options):
        timeframe = {"daily":"daily", "hourly":"hourly", "5min":"5min"}
        timeframe = timeframe[options["timeframe"].lower()]
        logger.info(f"start  to initiate attack for {timeframe} ipmetas.", {"command": "attack"})

        if timeframe != '5min' :
            payloads = Payload.objects.filter(generating=True)
            redis_db = {"daily":REDIS_IP_DAILY_DB, "hourly":REDIS_IP_HOURLY_DB}
            redis_db = redis_db[options["timeframe"]]
            keys = get_keys_from_redis(redis_db)
            dataset = load_objects_from_redis(keys,redis_db)
            logger.info(f"number of {options['timeframe']} ipmeta is {len(dataset)}.")
        
        else:    
            payloads = Payload.objects.filter(generating=True, using_lower_timeframe=True)
            daily_keys = get_keys_from_redis(REDIS_IP_DAILY_DB)
            daily_keys = [ip.decode('utf8') for ip in daily_keys]
            hourly_keys = get_keys_from_redis(REDIS_IP_HOURLY_DB)
            hourly_keys = [ip.decode('utf8') for ip in hourly_keys]
            gte = options["gte"]
            lt = options["lt"]
            gte = get_last_day(gte, timeframe='5min')
            lt =  get_last_day(lt, timeframe='5min')
            min5_ipmetas = produce_ipmeta_clickhouse(gte=gte, lt=lt,timeframe='Minutly', processor_number=REMEMBER_NUMBER_OF_PROCESSOR)
            min_5_ipmeta_dict = {ipmeta.ip:ipmeta for ipmeta in min5_ipmetas}
            min5_keys = min_5_ipmeta_dict.keys()
            
            daily_keys_common  = set(min5_keys).intersection(set(daily_keys))
            hourly_keys_common = set(hourly_keys).intersection(set(min5_keys) - daily_keys_common)
            remain_5min_keys   = set(min5_keys) - (daily_keys_common | hourly_keys_common)

            # daily_ipmeta_obj = load_objects_from_redis(daily_keys_common,REDIS_IP_DAILY_DB)
            # hourly_ipmeta_obj = load_objects_from_redis(hourly_keys_common,REDIS_IP_HOURLY_DB)
            # dataset = daily_ipmeta_obj +  hourly_ipmeta_obj  
            dataset = [] 
            remain_5_min_ips_obj = []
            for ip in  remain_5min_keys:
                ipmeta = min_5_ipmeta_dict[ip]
                obj = pickle.dumps(ipmeta)
                remain_5_min_ips_obj.append(obj)
            dataset.extend(remain_5_min_ips_obj)
            
            
            # min5_ipmetas.clear()
            # logger.info(f"number of daily ipmeta is {len(daily_ipmeta_obj)}.")
            # logger.info(f"number of hourly ipmeta is {len(hourly_ipmeta_obj)}.")
            # logger.info(f"number of 5 min ipmeta is {len(remain_5_min_ips_obj)}.")
            
        if len(dataset) > 0  and len(payloads) > 0:
            logger.info(f"start attack on {len(dataset)}", {"command": "attack"})
            detection  = Detection(payloads=payloads, dataset=dataset, timeframe=timeframe)
            detection.base_algorithm_attack()
            logger.info("done", {"command": "attack"})
        else:
            logger.error("Data or Payloads are not provided", {"command": "attack"})
