from rest_framework import serializers
from .models import AnalyzedPacket

class AnalyzedPacketSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalyzedPacket
        fields = '__all__'
