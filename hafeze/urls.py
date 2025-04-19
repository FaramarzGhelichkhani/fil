from django.urls import path

from . import views

app_name = 'hafeze'
urlpatterns = [
    path('api/', views.get_ipmeta_api, name='api'),
    path('ui/', views.get_ipmeta_ui, name='ui'),
    path('ip_traffic/', views.get_ip_traffic, name='ip_traffic')
]
