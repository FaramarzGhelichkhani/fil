from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

app_name = 'aaj'

router = DefaultRouter()
router.register(r'domains', views.DomainViewSet, basename="domains")
router.register(r'users', views.UserViewSet, basename="user")

urlpatterns = [
    path('ui/', views.UI.as_view(), name='ui'),
    path('get_domain_ips/<domain>', views.get_domain_ips, name='get_domain_ips'),
    path('get_domain_hit/<domain>', views.get_domain_hit, name='get_domain_hit'),
    path('', include(router.urls)),
]
