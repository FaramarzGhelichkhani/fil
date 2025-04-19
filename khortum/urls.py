from django.urls import path

from . import views

urlpatterns = [
    path('save/', views.save_input_ipmetas, name='save'),
    path('remove/', views.remove_input_ipmetas, name='remove'),
    path('download-file/', views.DownloadView.as_view(), name='download_file'),
]
