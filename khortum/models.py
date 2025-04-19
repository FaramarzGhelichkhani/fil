import datetime
from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.postgres.fields import ArrayField
from aaj.utils.ip_clustering import Clustering
from hafeze.utils.functions import fetch_input_ipmeta_from_fil
from khortum.utils.functions import payloadcheck
from utils.utils import dicttoIpMeta

class Payload(models.Model):
    payload = models.IntegerField()
    name = models.CharField(max_length=64, null=False)
    generating = models.BooleanField(default=True)
    sending_temp = models.BooleanField(default=False)
    sending_main = models.BooleanField(default=False)
    similarity = models.BooleanField(default=True)
    similarity_asn_condition =  models.BooleanField(default=True, null=True,  blank=True)
    # check 
    min_traffic_1GB =models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(1000.0)], default=1.0, null=True,  blank=True
    )
    dns_block_list  = ArrayField(models.CharField(max_length=255), blank=True, null=True, default=['anydns'])
    detection_block_list = ArrayField(models.CharField(max_length=12), blank=True, null=True, default=['27459p'])
    appid_block_list   = ArrayField(models.IntegerField(), blank=True, null=True, default=[27459])
    asn_block_list   = ArrayField(models.IntegerField(), blank=True, null=True, default=[0])
    using_lower_timeframe = models.BooleanField(default=False)
    
    def __str__(self):
        return str(self.payload)
    
    def apply_similarity(self):
        from khortum.utils.functions import apply_similarity_on_ip
        from aaj.utils.manager import send_output_ips_to_temp, send_output_ips_to_main

        app_ipmetas = sorted(fetch_input_ipmeta_from_fil(payload=self.payload,
                    offset_days=30),key=lambda x: x.time, reverse=True)[:10]

        similar = apply_similarity_on_ip(app_ipmetas,dist_type=None)
        out = []

        for row in similar:
            ip = row[1] 
            input_ip = row[0]
            ip.payload = self
            ip.source_ = 'fil-similar'
            ip.comment  = 'similar to '+ str(input_ip.ip) + '.'
            check, note =  payloadcheck(ip,self)
            if self.similarity_asn_condition:
                if ip.asn == input_ip.asn and check:
                    out.append(ip)
            else:
                if check:
                    out.append(ip)

        if self.sending_temp:
            send_output_ips_to_temp(out)
        if self.sending_main:
            send_output_ips_to_main(out)                    
        return out
    
    @classmethod
    def input_clustering(self,payload=None,ips=None):
        payload = self if payload is None else payload 
        if ips is None:
             ips = sorted(fetch_input_ipmeta_from_fil(payload=self.payload,
                    offset_days=14),key=lambda x: x.time, reverse=True)[:40]
        
        filterd_ips = list(filter(lambda x:  payloadcheck(x,payload)[0], ips))
        if len(set([ip.asn for ip in filterd_ips])) > 1 :
            clus = Clustering.get_clustering(filterd_ips, 'asn_dist')
            for key, values in clus.items():
                for val  in values:
                    if type(val.time)== list:
                        val.time= sorted(val.time, reverse=True)[0]
                clus[key] = sorted(values,key=lambda x: x.time, reverse=True)
            return clus
        else:
            return {0:filterd_ips}


class Source(models.Model):
    name = models.CharField(max_length=16, null=False)

    def __str__(self):
        return self.name


class IP(models.Model):

    APPROVED_CHECK = 'approved'
    CHECKING_CHECK = 'checking'
    BLOCKED_CHECK  = 'blocked'

    CHECK_CHOICES = [(APPROVED_CHECK,'approved'), (CHECKING_CHECK, 'checking'), (BLOCKED_CHECK, 'blocked')]

    ip = models.GenericIPAddressField(protocol='IPv4', unpack_ipv4=False, null=False)
    payload = models.ForeignKey(Payload, on_delete=models.CASCADE, null=False)
    generator = models.GenericIPAddressField(protocol='IPv4', unpack_ipv4=False, null=False)
    insert_time = models.DateTimeField(default=timezone.now, null=False)
    source = models.ForeignKey(Source, null=False, on_delete=models.CASCADE)
    signature = models.IntegerField(null=True, blank=True)
    type = models.CharField(default="manual-admin", max_length=64, null=False)
    distance = models.FloatField(default=0)
    check = models.CharField(max_length=8, null=True, blank=True, choices=CHECK_CHOICES, default=CHECKING_CHECK)
    attack_counter = models.IntegerField(default=0,null=True, blank=True)
    update_time = models.DateTimeField(default=timezone.now, null=True, blank=True)
    update_counter = models.IntegerField(default=0,null=True, blank=True)
    note = models.TextField(null=True, blank=True)

    class Meta:
        constraints = [
        models.UniqueConstraint(fields=['ip', 'payload','source','generator','type'], name='unique_ip')
    ]

    def __str__(self):
        return str(self.ip)

    def get_ipmeta(self):
        note_ = self.note.replace("tzinfo=<UTC>", "")
        dict_ip = eval(note_)
        ipMeta = dicttoIpMeta([dict_ip])[0]   
        return ipMeta
