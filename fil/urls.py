from django.contrib import admin
from django.urls import include
from django.urls import path
from fil.settings import IS_PRODUCTION, VERSION
from fil import views
     

header = f'Fil Production {VERSION}' if IS_PRODUCTION else 'Fil Development'
admin.site.site_header = header
admin.site.site_title = ':)'

urlpatterns = [
    path('fil/get/', include('hafeze.urls')),
    path('fil/script/', include('aaj.urls')),
    path('fil/input/', include('khortum.urls')),
    path('fil/admin/', admin.site.urls),
    path('fil/simple_test', views.simple_test_view, name='simple_test'),
    path('fil/test_response/<number>', views.test_response, name='test_response'),
    path('api-auth/', include('rest_framework.urls')),
    path('fil/api/docs/', views.schema_view.with_ui('redoc', cache_timeout=0) ,  name='swagger'),

]
