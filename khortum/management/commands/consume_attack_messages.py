import logging
from django.core.management.base import BaseCommand
from utils.file_handler import load_objects_from_redis, get_keys_from_redis
from fil.settings import IS_HOURLY, REDIS_IP_HOURLY_DB
from khortum.utils.queue_handler import KafkaQueueHandler

logger = logging.getLogger("ip_classification.main")

class Command(BaseCommand):
    help = "Consume messeges from kafka"

    def handle(self, *args, **options):

        keys = get_keys_from_redis(REDIS_IP_HOURLY_DB)
        cache_data_pickled = load_objects_from_redis(keys,REDIS_IP_HOURLY_DB)
        
        kafka_handler  = KafkaQueueHandler(database_ipmeta=cache_data_pickled)
        logger.info(f"start fetching data to attack")
        kafka_handler.read_attack_messeges()
        