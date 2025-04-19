from django.contrib import admin
from khortum.utils.actions import  apply_ip_similairty, apply_payload_similarity, produce_ipmeta_action
from .models import IP
from .models import Payload
from .models import Source


class SourceAdmin(admin.ModelAdmin):
    fields = ('name',)
    # list of fields to display in django admin
    list_display = ['name']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['name__contains']
    # to define model data list ordering
    ordering = ('name',)


class PayloadAdmin(admin.ModelAdmin):
    fields = ('payload', 'name', 'generating', 'sending_temp', 'sending_main',\
        'similarity','similarity_asn_condition','using_lower_timeframe',\
        'min_traffic_1GB', 'dns_block_list', 'detection_block_list','appid_block_list','asn_block_list')
    # list of fields to display in django admin
    list_display = ['payload', 'name', 'generating', 'sending_temp', 'sending_main']
    list_editable = ['generating', 'sending_temp', 'sending_main']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['payload__contains']
    # to define model data list ordering
    ordering = ('payload', 'name', 'generating', 'sending_temp', 'sending_main')

    
    actions = [apply_payload_similarity]

class IPAdmin(admin.ModelAdmin):
    fields = ('ip', 'payload', 'generator', 'insert_time','update_time', 'source', 'type','distance','check','update_counter','attack_counter','note')
    # list of fields to display in django admin
    list_display = ['ip', 'payload', 'generator', 'type', 'insert_time', 'update_time','source','check', 'update_counter']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['ip__contains']
    # to define model data list ordering
    ordering = ('-update_time',)
    list_filter = ('source', 'payload','check')

    actions = [produce_ipmeta_action,apply_ip_similairty]# apply_port_similairty, apply_dns_similairty, apply_domain_similairty]

admin.site.register(Payload, PayloadAdmin)
admin.site.register(Source, SourceAdmin)
admin.site.register(IP, IPAdmin)
