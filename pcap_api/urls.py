from django.urls import path
from core.views import UploadAndAnalyzePCAPView, AnalysisResultsAPI
urlpatterns = [
    path('api/upload/', UploadAndAnalyzePCAPView.as_view(), name='upload-pcap'),
    path('api/analysis/', AnalysisResultsAPI.as_view(), name='analysis-results'),
]

