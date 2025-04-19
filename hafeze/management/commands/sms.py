import logging
import shutil
import requests
import datetime
import json
from django.core.management.base import BaseCommand
from fil.settings import SMS_LOG_ADDRESS
from django.db.models import Count, Q
from khortum.models import IP, Source
from django.utils import timezone
from utils.utils import  initialize_sms_data, save_sms_data
from hafeze.models import ClusterRef, IpCluster

logger = logging.getLogger("ip_classification.main")
_, columns = shutil.get_terminal_size()
line = '-' * columns

class Command(BaseCommand):
    help = "genreate messeges for sms."
    
    def add_arguments(self, parser):
        parser.add_argument('hours' , type=int, help='number of hours')
        parser.add_argument('--output', dest='output_path', type=str, default=SMS_LOG_ADDRESS, help='Output file path')

    def handle(self, *args, **options):
        n_hours = options['hours']
        path = options['output_path']

        input_source = Source.objects.filter(Q(name='input') | Q(name='spider'))
        output_source = Source.objects.get(name='output')
        time_threshold = timezone.now() - datetime.timedelta(hours=n_hours)
        filterd_data  = IP.objects.filter(update_time__gte=time_threshold)# payload__generating=True
        
        input_data = filterd_data.filter(source__in=input_source) 
        ouput_data = filterd_data.filter(source=output_source) 
            
        input_stats = input_data.values('payload__payload').annotate(
            ip_count_check_approved=Count('ip', filter=Q(check=IP.APPROVED_CHECK), distinct=True),
            ip_count_check_blocked =Count('ip', filter=Q(check=IP.BLOCKED_CHECK), distinct=True),
            ip_count_check_check   =Count('ip', filter=Q(check=IP.CHECKING_CHECK), distinct=True),)
        
        output_stats = ouput_data.values('payload__payload','type').annotate(
            ip_count_check_approved=Count('ip', filter=Q(check=IP.APPROVED_CHECK), distinct=True),
            ip_count_check_blocked =Count('ip', filter=Q(check=IP.BLOCKED_CHECK), distinct=True),)

        output_attack = ouput_data.values('update_time__hour').annotate(
            ip_counts=Count('ip', distinct=True)).filter(ip_counts__gt=0)\
                .values_list('update_time__hour', flat=True)

        attack_failed_count = n_hours - len(output_attack)
        # partitioning
        new_clusters =  ClusterRef.objects.filter(created_at__gte=time_threshold).values('id').distinct().count() 
        checked_ips  =  IpCluster.objects.filter(updated_at__gte=time_threshold).values('ip').distinct().count()
        partitioning_data = [{'new_clusters':new_clusters, 'checked_ips':checked_ips}]

        initialize_sms_data()
        save_sms_data(None, f"attack failed hours: {attack_failed_count}")
        self.wirte_data(None,path,'a')
        self.wirte_data(input_stats,path)
        self.wirte_data(output_stats, path,'a')
        self.wirte_data(partitioning_data, path,'partitioning')
  

    def wirte_data(self,result, path, mode='w'):
        output_line = ''
        with open(path, 'a') as output_file:
            if result is not None:
                for item in result:
                    payload = item.get('payload__payload',None)
                    type = item['type'].replace("manual-", "").replace("signature","sign").replace("similarity","sim") if 'type' in item else None
                    ip_count_check_approved = item.get('ip_count_check_approved', None)
                    ip_count_check_blocked  = item.get('ip_count_check_blocked', None)
                    ip_count_check_check    = item.get('ip_count_check_check',None) 
                    new_clusters    = item.get('new_clusters',None) 
                    checked_ips    = item.get('checked_ips',None) 
                    if mode == 'w':
                        output_line += f"{payload}-{ip_count_check_approved:02d}-{ip_count_check_blocked:02d}-{ip_count_check_check:02d}\n"
                    elif mode == 'a':
                        output_line += f"{payload}-{type}-{ip_count_check_approved:02d}-{ip_count_check_blocked:02d}\n"
                    
            
            if mode == 'w':
                header = "Payload-Approved-Blocked-Checking\n"
                output_file.write(header)
            elif mode == 'partitioning':
                header = "new clusters- number of checked ips\n"
                output_file.write(header)
                output_line = f"{new_clusters:02d}-{checked_ips:02d}\n"     
            
            output_file.write(f"{line}\n")
            output_file.write(output_line)
            