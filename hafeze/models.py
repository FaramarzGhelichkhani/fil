import ipaddress
from django.db import models
from khortum.models import Payload, Source

class ResultCheck(models.Model):
    ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False, null=False)
    payload = models.ForeignKey(Payload, on_delete=models.CASCADE, null=False)
    source = models.ForeignKey(Source, null=False, on_delete=models.CASCADE)
    payload_check_result = models.BooleanField(default=False,  null= True, blank=True)
    signature_check_result = models.BooleanField(default=False, null= True, blank=True)
    ml_check_result = models.BooleanField(default=False, null= True, blank=True)
    insert_time = models.DateTimeField(null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True) 
    note = models.CharField(max_length=768, null=True, blank=True)
    def __str__(self):
        return f"{self.ip}: {self.payload_check_result}"

    class Meta:
        verbose_name = "Result Check"
        verbose_name_plural = "Result Checks"
        ordering = ["-created_at"]
        db_table = "result_check"
        constraints = [models.UniqueConstraint(fields=['ip', 'payload','source'], name='unique_ip_payload_source')]


class Tag(models.Model):
    name = models.CharField(max_length=256, null=False)

    def __str__(self):
        return str(self.name)

class ClusterRef(models.Model):
    cluster_label = models.CharField(max_length=326, null=True, blank=True)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True) 
    detection_source = models.CharField(max_length=12, default='other')
    note = models.CharField(max_length=768, null=True, blank=True)
    
    def __str__(self):
        return f"{self.id}__{self.cluster_label}_{self.tag}"

    class Meta:
        verbose_name = "Cluster Ref"
        verbose_name_plural = "Cluster Refs"
        ordering = ["-created_at"]
        db_table = "cluster_ref"
        # constraints = [models.UniqueConstraint(fields=['cluster_label', 'detection_source','tag'], name='unique_label_detection_tag')]

class IpCluster(models.Model):
    cluster = models.ForeignKey(ClusterRef, on_delete=models.CASCADE, null=False)
    ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False, null=False)
    asn = models.CharField(max_length=68, null=True, blank=True)
    traffic = models.BigIntegerField()
    # asn_organization = models.CharField(max_length=256, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    update_counter = models.IntegerField(default=0,null=True, blank=True)
    note = models.TextField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.ip}, {self.cluster}"

    def get_ip(self):
        addr = ipaddress.ip_address(self.ip)
        return addr.exploded    

    class Meta:
        verbose_name = "Ip Cluster"
        verbose_name_plural = "Ip Clusters"
        ordering = ["-updated_at"]
        db_table = "ip_cluster"
        constraints = [models.UniqueConstraint(fields=['ip', 'cluster'], name='unique_ip_cluster')]

class IpDistance(models.Model):
    ip1 = models.GenericIPAddressField(protocol='both', unpack_ipv4=False, null=False,verbose_name='ip1')
    ip2 = models.GenericIPAddressField(protocol='both', unpack_ipv4=False, null=False,verbose_name='ip2')
    distance = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"({self.ip1}, {self.ip2}): {self.distance}"
        
    def get_ip(self,ip):
        addr = ipaddress.ip_address(ip)
        return addr.exploded 
    class Meta:
        verbose_name = "Ip Distance"
        verbose_name_plural = "Ip Distances"
        ordering = ["-created_at"]
        db_table = "ip_distances"
        constraints = [models.UniqueConstraint(fields=['ip1', 'ip2'], name='unique_ip1_ip2')]
