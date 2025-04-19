import logging
from django.core.management.base import BaseCommand
from hafeze.utils.partitioning import Partition
from fil.settings import REDIS_IP_HOURLY_DB, REDIS_IP_DAILY_DB
logger = logging.getLogger("ip_classification.main")
        
class Command(BaseCommand):
    help = "Clustering ips."

    def add_arguments(self, parser):
        parser.add_argument('-d', "--detection", type=str, default='other', required=False)
        parser.add_argument('-p', "--percent",  type=int, default=50)

    def handle(self, *args, **options):

        traffic_type = {'freeze': 'freeze', 'iran':'Iran', 'other': 'other'}
        redis_db = {"freeze":REDIS_IP_DAILY_DB, "Iran":REDIS_IP_DAILY_DB,"other":REDIS_IP_HOURLY_DB}
        detection_source = traffic_type[options['detection'].lower()]
        logger.info(f"detection: {detection_source}")     
        p =  Partition(percent=options['percent'], detection_source=detection_source, redis_db=redis_db[detection_source] )
        p.base_partitioning_algorithm()
        logger.info("clustering Done.")     
