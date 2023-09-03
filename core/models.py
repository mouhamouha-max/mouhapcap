from django.db import models

class AnalyzedPacket(models.Model):
    file_identifier = models.CharField(max_length=100)
    sip_info = models.JSONField()  # Utilisation du champ JSONField pour stocker du JSON
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Analyzed Packet {self.id}"
