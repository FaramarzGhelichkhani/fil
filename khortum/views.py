import json
import os
import pickle

from django.http import HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.views import View
from fil.settings import INPUT_DATA_PATH
from utils.ipmeta.main import produce_ipmeta
from utils.utils import get_last_day

@csrf_exempt
def save_input_ipmetas(request):
    data = json.loads(request.body)
    data = json.loads(data)

    lte = int(data['days_ago'])
    gte = lte + 1
    try:
        ipmetas = produce_ipmeta(
            gte=get_last_day(gte),
            lte=get_last_day(lte),
            args=data['ip_list'],
            size=len(data['ip_list'])
        )

        data_dir = INPUT_DATA_PATH + str(data['payload']) + '/'
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        data_path = data_dir + f"{data['name']}.obj"
        with open(data_path, 'wb') as writer:
            pickle.dump(ipmetas, writer)
        return FileResponse(open(data_path, 'rb'))
    except Exception as e:
        return HttpResponse(e)


@csrf_exempt
def remove_input_ipmetas(request):
    data = json.loads(request.body)
    data = json.loads(data)

    try:
        data_dir = INPUT_DATA_PATH + str(data['payload']) + '/'
        data_path = data_dir + f"{data['name']}.obj"
        os.remove(data_path)
        return HttpResponse()
    except Exception as e:
        return HttpResponse(e)

class DownloadView(View):
    def get(self, request):
        file_path = "distance_output.txt"  
        
        with open(file_path, "rb") as file:
            response = FileResponse(file)
            response['Content-Disposition'] = 'attachment; filename="distance_output.txt"'
            # os.remove(file_path)
            return response
