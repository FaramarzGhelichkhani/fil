from aaj.utils.manager import send_output_ipmetas, send_output_ips_to_fil
from fil.settings import IS_HOURLY
from khortum.utils.functions import apply_similarity_on_ip, download_file_response, fetch_ipmeta, payloadcheck
from utils.ipmeta.main import produce_ipmeta, produce_ipmeta_clickhouse
from utils.utils import get_last_day
from khortum.models import IP, Source
from django.contrib import messages

def apply_payload_similarity(modeladmin,request,queryset):
        try:
            if len(queryset) >  1 : 
                raise Exception("too much payload. select only one payload!")
            for payload in queryset:
                print(payload.payload)
                similar = payload.apply_similarity()
                messages.success(request, f"{len(similar)}  ip's detected for payload {payload.payload}.")
                file_data = ["input_ip,payload,comment"] + [
                    f"{row.ip},{row.payload},{row.comment}" for row in similar
                ]
                response = download_file_response(file_data=file_data, filename="distance_output.txt")
                response['Content-Type'] = 'application/octet-stream'
                response['Content-Disposition']  = 'attachment; filename="similar_output.txt"'
                return response
        except Exception as e :
            messages.error(request,e)

apply_payload_similarity.short_description = "apply similairty for payload."

def apply_ip_similairty(modeladmin,request,queryset):
    try:
        ipmetas = fetch_ipmeta(queryset=queryset)
        similar = apply_similarity_on_ip(ipmetas,dist_type=None)
        file_data = ["input_ip,similar_ip"] + [
            f"{row[0]},{row[1]}" for row in similar

        ]
        response = download_file_response(file_data=file_data, filename="distance_output.txt")
        response['Content-Disposition'] = 'attachment; filename="distance_output.txt"'
        return response
    except Exception as e:
        messages.error(request,e)    

apply_ip_similairty.short_description = "find similar ip"

def apply_port_similairty(modeladmin,request,queryset):
    
    try:
        ipmetas = fetch_ipmeta(queryset=queryset)
        similar = apply_similarity_on_ip(ipmetas,dist_type='port')
        file_data = ["input_ip,similar_ip,port_similarity_chance"] + [
            f"{row[0].ip},{row[1].ip},{row[2]}" for row in similar
        ]
        response = download_file_response(file_data=file_data, filename="distance_output.txt")
        response['Content-Disposition'] = 'attachment; filename="distance_output.txt"'
        return response
    except Exception as e:
        messages.error(request,e)
             
apply_port_similairty.short_description = "find similar port"


def apply_dns_similairty(modeladmin,request,queryset):
    try:
        ipmetas = fetch_ipmeta(queryset=queryset)
        similar = apply_similarity_on_ip(ipmetas,dist_type='dns')
        file_data = ["input_ip,similar_ip,dns_similarity_chance"] + [
            f"{row[0].ip},{row[1].ip},{row[2]}" for row in similar
        ]
        response = download_file_response(file_data=file_data, filename="distance_output.txt")
        response['Content-Disposition'] = 'attachment; filename="distance_output.txt"'
        return response
    except Exception as e:
        messages.error(request,e)     
apply_dns_similairty.short_description = "find similar dns"

def apply_domain_similairty(modeladmin,request,queryset):
    try:
        ipmetas = fetch_ipmeta(queryset=queryset)
        similar = apply_similarity_on_ip(ipmetas,dist_type='domain')
        file_data = ["input_ip,similar_ip,domain_similarity_chance"] + [
            f"{row[0].ip},{row[1].ip},{row[2]}" for row in similar
        ]
        response = download_file_response(file_data=file_data, filename="distance_output.txt")
        response['Content-Disposition'] = 'attachment; filename="distance_output.txt"'
        return response
    except Exception as e:
        messages.error(request,e)     
apply_domain_similairty.short_description = "find similar domain"


def produce_ipmeta_action(modeladmin,request,queryset):
    ips_dict = {ip.ip:ip for ip in queryset}
    ips_list = [ip.ip for ip in queryset]
    
    try:
        if IS_HOURLY:
            ipmetas = produce_ipmeta_clickhouse(gte=get_last_day(2),lt=get_last_day(1),ips=ips_list)
        else:
            ipmetas = produce_ipmeta(gte=get_last_day(1), lte=get_last_day(0),
                                            args=ips_list,
                                            size=len(ips_list))

        if len(ipmetas) == 0:
            raise Exception("no ipmeta generated.")                                    
        
        output_list_ip = []
        output_ipmetas = []
        input_source = Source.objects.get(name='input')
        for ipmeta in ipmetas:
            if ipmeta.ip in ips_dict:
                Ip = ips_dict[ipmeta.ip]
                check, note =  payloadcheck(ipmeta=ipmeta, payload=Ip.payload)
                output_list_ip.append(IP(ip=Ip.ip, payload=Ip.payload,
                           generator='0.0.0.0',
                           source=input_source,
                           distance=0,
                           check=  IP.APPROVED_CHECK if check else IP.BLOCKED_CHECK,
                           note= note if note != None else '', 
                          type='manual-admin')
                )
                if check:
                    output_ipmetas.append(ipmeta)     
        
        send_output_ipmetas(output_ipmetas,get_last_day(0))
        messege = "ipmeta inserted." if len(output_ipmetas) > 0 else "ipmetas not passed check conditions."
        messages.success(request, messege)
        send_output_ips_to_fil(output_list_ip)
        messages.success(request, f"{len(output_list_ip)}  ip's instances produced.")
    except Exception as e:
        messages.error(request, f"something wrong happend. data not produced.")
        messages.error(request, e)    

produce_ipmeta_action.short_description = "produce ipmeta and save in database"
