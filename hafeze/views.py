import json
import os
import pickle
from pathlib import Path

from django.http import HttpResponse, FileResponse
from django.http import JsonResponse
from django.shortcuts import render
from django.http import HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view

from fil.settings import REDIS_IP_HOURLY_DB
from .decorators import swagger_auto_schema_ip_traffic, swagger_auto_schema_ipmeta_api, swagger_auto_schema_ipmeta_ui
from utils.file_handler import load_objects_from_redis
from utils.ipmeta.main import ipmeta_aggregator, produce_ipmeta, produce_ipmeta_clickhouse
from utils.utils import get_last_day, todict
from .forms import IpmetaForm



from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status

import logging

logger = logging.getLogger("hafeze.views")
DIR = Path(__file__).resolve().parent.parent
with open(os.path.join(DIR, '.env.json'), 'r') as f:
    config = json.load(fp=f)


def retrieve(ips):
    result = []
    keys = ips
    all_unlabeled_pickle = load_objects_from_redis(keys, REDIS_IP_HOURLY_DB)

    for object in all_unlabeled_pickle:
        ipmeta = pickle.loads(object)
        if ipmeta.ip in ips:
            result.append(ipmeta)
    return result


@csrf_exempt
@swagger_auto_schema_ipmeta_api
@api_view(['POST'])
def get_ipmeta_api(request):
    try:
        # data = json.loads(json.loads(request.body))
        data = json.loads(request.data)
        date_offset = int(data['days_ago'])
        gte  =  get_last_day(0 + date_offset)
        lt   =  get_last_day(0)
        timeframe = 'Daily'
        if data['ip_list'] == [] or len(data['ip_list']) > 100:
            raise SyntaxError
        ipMetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=data['ip_list'],timeframe=timeframe)
        ipmetas = ipmeta_aggregator(ipmetas=ipMetas)
        data_respond = []
        for ipmeta in ipmetas:
            ipdict = todict(ipmeta)
            data_respond.append(ipdict) 
        return JsonResponse(data_respond, safe=False)
    except Exception as e:
        return HttpResponse(e)



@csrf_exempt
@swagger_auto_schema_ip_traffic 
@api_view(['POST'])
def get_ip_traffic(request):   
    """
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.data)
            ipmetas = retrieve(ips=data['ips'])
            out = []
            total_traffic = 0
            for ipmeta in ipmetas:
                total_traffic += ipmeta.total_traffic
                out.append({
                    'ip': ipmeta.ip,
                    'traffic': ipmeta.total_traffic,
                    'time': ipmeta.time,
                    'asn': ipmeta.asn
                })
            result = {'data': out, 'total_traffic': total_traffic}
            return HttpResponse(json.dumps(result), content_type="application/json")
        except json.JSONDecodeError:
            # Return a bad request response if the JSON data is invalid
            return HttpResponseBadRequest('Invalid JSON data')
    else:
        # Return a bad request response for all other request methods
        return HttpResponseBadRequest('Unsupported request method')

@swagger_auto_schema_ipmeta_ui
@api_view(['POST', 'GET'])
def get_ipmeta_ui(request):
    if request.method == 'POST':
        form = IpmetaForm(request.POST)
        data = {}
        # check whether it's valid:
        if form.is_valid():
            try:
                data['ips'] = form.cleaned_data['ips'].replace(' ', '').replace("'", '').split(',')
                data['days_ago'] = form.cleaned_data['days_ago']
                data['produce'] = form.cleaned_data['produce']
                data['download'] = form.cleaned_data['download']
                if data['produce']:
                    if data['days_ago'] is None:
                        data['days_ago'] = 1
                    lte = int(data['days_ago'])
                    gte = lte + 1
                    ipmetas = produce_ipmeta(gte=get_last_day(gte), lte=get_last_day(lte),
                                             args=data['ips'], size=len(data['ips']))
                else:
                    ipmetas = retrieve(ips=data['ips'])

                out = [todict(ipmeta) for ipmeta in ipmetas]
                if data['download']:
                    return JsonResponse(out, safe=False)
                else:
                    result = json.dumps(out, indent=4)
                    return render(request, 'signature.html', {'form': form, 'result': result})
            except Exception as e:
                data['download'] = False
                out = str(e)
                result = json.dumps(out, indent=4)
                return render(request, 'signature.html', {'form': form, 'result': result})

    else:
        form = IpmetaForm()
    return render(request, 'ipmeta.html', {'form': form})
