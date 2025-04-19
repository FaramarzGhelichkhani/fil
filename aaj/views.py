import datetime
import glob
import ipaddress
import json
import logging
import os
import pickle
import random
import re
import traceback

import numpy as np
import pandas as pd
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import permissions, viewsets
from rest_framework.permissions import IsAdminUser
from rest_framework.views import APIView
from rest_framework.decorators import api_view

from khortum.utils.functions import payloadcheck
from .decorators import swagger_auto_schema_domain_ips, swagger_auto_schema_domain_hit, swagger_auto_schema_UI, swagger_auto_schema_UI_GET

from aaj.models import Author, Signature
from aaj.models import Domain
from aaj.permissions import IsOwnerOrReadOnly
from aaj.serializers import DomainSerializer
from aaj.serializers import UserSerializer
from aaj.utils.manager import manage, send_output_ips_to_main, send_output_ips_to_temp
from aaj.utils.manager import fetch_ipmetas_of_labeled_ips
from fil.settings import IS_HOURLY, DATA_PATH, REDIS_IP_HOURLY_DB, REMEMBER_BATCH_SIZE, REMEMBER_FETCH_SIZE, ATTACK_SPLIT_SIZE, \
    REDIS_TMP_DB
from fil.settings import config
from khortum.models import IP, Payload, Source
from utils.file_handler import get_keys_from_redis, load_objects_from_redis, load_domain_from_redis, \
    load_saved_object_from_redis
from utils.ipmeta.main import get_domain_meta
from .forms import SignatureForm
from aaj.utils.distance import Utils

logger = logging.getLogger("ip_classification.main")

# me
from django.http import HttpResponse


class UI(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema_UI_GET
    def get(self, request, format=None):
        form = SignatureForm()
        return render(request, 'signature.html', {'form': form})

    @swagger_auto_schema_UI
    def post(self, request, format=None):
        form = SignatureForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            try:
                download = form.cleaned_data['download']

                input_ips = str(form.cleaned_data['input_ips']).replace(' ', '').replace("'", '').split(',')
                if '' in input_ips: input_ips.remove('')
                logger.info(f"got {len(input_ips)} inputs: {input_ips}")

                unlabeled_limit = int(form.cleaned_data['unlabeled_limit'])
                script = form.cleaned_data['signature']
                username = request.user.username
                author = Author(name=username)
                app = Payload(payload=27227)
                name = "Test Sign Api"
                signature = Signature(author=author, payload=app, name=name, script=script,
                                      needs_input=len(input_ips) > 0)
                keys = load_saved_object_from_redis("sorted_ip_list", REDIS_TMP_DB)
                logger.info(f"redis has {len(keys)} ipmetas")
                limited_keys = keys[:unlabeled_limit]
                all_unlabeled_ipmetas = load_objects_from_redis(limited_keys, REDIS_IP_HOURLY_DB)
                all_labeled_ips = []
                source = Source(name='input')
                for ip in input_ips:
                    all_labeled_ips.append(IP(ip=ip, payload=app, generator=ip, source=source, type="aaj-api"))

                output_ips, output_ips_prime, errors = manage([app], [signature], all_labeled_ips,
                                                              all_unlabeled_ipmetas)

                app_ipmetas = fetch_ipmetas_of_labeled_ips([app], all_labeled_ips)
                labeled_ipmetas = {ipmeta.ip: ipmeta for ipmeta in app_ipmetas[app.payload]}
                unlabeled_ipmetas = {ipmeta.ip: ipmeta for ipmeta in output_ips_prime}
                data = []
                for ip in output_ips:
                    ip_dict = {
                        'ip': ip.ip,
                        'generator': ip.generator,
                        'traffic': unlabeled_ipmetas[ip.ip].total_traffic / 1e12
                    }
                    if ip.generator != '0.0.0.0':
                        ip_dict.update(Utils.get_distance(unlabeled_ipmetas[ip.ip], labeled_ipmetas[ip.generator]))
                    data.append(ip_dict)
                if len(data) > 0:
                    data = pd.DataFrame(data, index=list(range(len(data)))).set_index('ip')
                    data.sort_values(by=['traffic'], inplace=True, ascending=False)
                    data = np.round(data, 2)
                    data = data.to_string()
                out = {'data': data, 'errors': errors}
            except:
                download = False
                out = {'data': '', 'errors': traceback.format_exc()}
            if download:
                return JsonResponse(out, safe=False)
            else:
                errors = json.dumps(out['errors'], indent=4)
                data = out['data']
                return render(request, 'signature.html', {'form': form, 'result': data, 'errors': errors})
        return render(request, 'signature.html', {'form': form})


@swagger_auto_schema_domain_ips
@api_view(['GET'])
def get_domain_ips(request, domain):
    try:
        logger.info(f"'{domain}'")
        pattern = re.compile(".*([\w|-]+\.[\w]+)$")
        if not pattern.match(domain):
            return HttpResponse(json.dumps({'error': 'Domain must be in following format: "^([\w]+\.[\w])+$"'}),
                                content_type="application/json")
        domain = re.search('([\w|-]+\.[\w]+)$', domain).group(1)

        resolved_ips, server_ips = load_domain_from_redis(domain)
        domainMeta = get_domain_meta(domain=domain, resolved_ips=resolved_ips, server_ips=server_ips)
        if domainMeta is None:
            result = {
                'domain': domain,
                'server_ips': []
            }
            return HttpResponse(json.dumps(result), content_type="application/json")

        dnsIPs_raw = [x.ip for x in domainMeta.resolved_ips]
        dnsASN = [x.asn for x in
                  list(filter(lambda o: True if o.percent >= 0.9 and o.hit > 1000 else False, domainMeta.resolved_ips))]
        serverIP = [x.ip for x in list(
            filter(lambda o: True if (o.asn in dnsASN and o.percent >= 0.5) else False, domainMeta.server_ips))]
        ip_list = list(filter(lambda x: not ipaddress.IPv4Address(x).is_private, list(set(serverIP))))
        ip_list.sort()
        result = {
            'domain': domain,
            'server_ips': ip_list,
            'resolved_ips_raw': dnsIPs_raw,
            'suggested_ips': list(set(dnsIPs_raw + serverIP))
        }
        return HttpResponse(json.dumps(result), content_type="application/json")
    except Exception as e:
        return HttpResponse(json.dumps(e), content_type="application/json")

@swagger_auto_schema_domain_hit
@api_view(['GET'])
def get_domain_hit(request, domain):
    try:
        resolved_ips, server_ips = load_domain_from_redis(domain)
        domainMeta = get_domain_meta(domain=domain, resolved_ips=resolved_ips, server_ips=server_ips)
        if domainMeta:
            hit = sum([x.hit for x in domainMeta.resolved_ips])
            result = {
                'domain': domain,
                'hit': hit
            }
        else:
            result = {
                'domain': domain,
                'ip': []
            }
        return HttpResponse(json.dumps(result), content_type="application/json")
    except Exception as e:
        return HttpResponse(json.dumps(e), content_type="application/json")


class DomainViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

def apply_signature(signature):
    from aaj.utils.worker import Worker
    from fil.settings import ATTACK_CORE_NUMBER
    from hafeze.utils.functions import fetch_input_ipmeta_from_fil

    keys = get_keys_from_redis(REDIS_IP_HOURLY_DB)
    all_unlabeled = load_objects_from_redis(keys, REDIS_IP_HOURLY_DB)
    print("unlabeld ipmetas :", len(all_unlabeled))
    try:
        app = signature.payload
        if signature.needs_input:
            # latest 10 input-ipmetas in fil during last 30 days.
            app_ipmetas = sorted(fetch_input_ipmeta_from_fil(payload=app.payload,source='input',offset_days=30),key=lambda x: x.time, reverse=True)[:10] 
            if len(app_ipmetas) == 0 :
                raise  Exception("there is no input ip for this payload in latst 30 days.")
        else:
            app_ipmetas = None    
        
        worker_info = f'apply signature for payload {app.payload}'
        worker = Worker(worker_info, app, signature, app_ipmetas, insert_date=None)
        output_list, output_list_prime, error_list = worker.find_similar_ips_multiprocess(all_unlabeled,ATTACK_CORE_NUMBER)
    # check 
        for index, ipmeta in enumerate(output_list_prime):
            ip = output_list[index]
            check, note = payloadcheck(ipmeta, ip.payload)
            if check:
                ip.check = IP.APPROVED_CHECK
            else:
                ip.check = IP.BLOCKED_CHECK
                ip.note = note
    # insert 
        if signature.sending_temp:
            send_output_ips_to_temp(output_list)
        if signature.sending_main:
            send_output_ips_to_main(output_list)
    except Exception as e:
        logger.error(str(e))
        raise e  

    return len(output_list)
