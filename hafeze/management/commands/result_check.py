import logging
from django.core.management.base import BaseCommand
from fil.settings import IS_HOURLY
from khortum.utils.queue_handler import KafkaQueueHandler

logger = logging.getLogger("ip_classification.main")

class Command(BaseCommand):
    help = "Consume check messeges from kafka"

    def handle(self, *args, **options):
        if not IS_HOURLY:
            kafka_handler  = KafkaQueueHandler(database_ipmeta=None)
            logger.info(f"start fetching data to check result.")
            kafka_handler.read_check_messeges()
        else:
            self.stdout.write(self.style.WARNING('hoourly server not check results.'))    
            