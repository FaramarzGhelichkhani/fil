from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from drf_yasg.views import get_schema_view
from rest_framework.permissions import AllowAny
from drf_yasg import openapi
from django.urls import path,  include
import aaj.views as views
from fil.settings import  VERSION

def simple_test_view(request):
    return HttpResponse("hi")


@api_view()
def test_response(request, number):
    return Response(number)


included_paths = [
   path('fil/get/', include('hafeze.urls')),
    path('fil/script/ui/', views.UI.as_view(), name='ui'),
    path('fil/script/get_domain_ips/<domain>', views.get_domain_ips, name='get_domain_ips'),
    path('fil/script/get_domain_hit/<domain>', views.get_domain_hit, name='get_domain_hit'),
]

schema_view = get_schema_view(
    openapi.Info(
        title="Fil API Documentation",
        default_version='v'+ VERSION,
        description="API documentation generated using Swagger",
    ),
    public=True,
    permission_classes=(AllowAny,),
    patterns=included_paths,
)
