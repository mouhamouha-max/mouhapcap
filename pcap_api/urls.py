from django.urls import path
from core.views import UploadAndAnalyzePCAPView, AnalysisResultsAPI, RegisterUser
from django.contrib import admin
urlpatterns = [
    path('api/upload/', UploadAndAnalyzePCAPView.as_view(), name='upload-pcap'),
    path('api/analysis/', AnalysisResultsAPI.as_view(), name='analysis-results'),
    path('/api/register', RegisterUser.as_view(), name='register'),
    path('admin', admin.site.urls),

]

