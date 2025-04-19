import logging
from django.core.management.base import BaseCommand
from utils.file_handler import load_objects_from_redis, get_keys_from_redis
from khortum.utils.queue_handler import KafkaQueueHandler

logger = logging.getLogger("ip_classification.main")



class Command(BaseCommand):
    help = "Consume messeges from kafka"

    def handle(self, *args, **options):
        
        kafka_handler  = KafkaQueueHandler(database_ipmeta=None)
        logger.info(f"start fetching input data.")
        kafka_handler.read_input_messeges()
