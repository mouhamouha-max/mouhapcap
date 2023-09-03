from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from scapy.all import rdpcap
from django.utils import timezone
import binascii
import re
from datetime import datetime
from decimal import Decimal
from scapy.layers.inet import IP

class UploadAndAnalyzePCAPView(APIView):
    max_data_list_size = 10  # Définissez la taille maximale de la liste
    file_analyzed_packets = {}
    parser_classes = (MultiPartParser,)

    @classmethod
    def get_latest_data(cls):
        latest_file_identifier = max(cls.file_analyzed_packets.keys(), default=None)

        if latest_file_identifier is not None:
            # Récupérez la liste de paquets SIP pour le dernier fichier téléchargé
            data_list = cls.file_analyzed_packets.get(latest_file_identifier, [])
            return data_list
        else:
            return []

    def extract_sip_info(self, packet):
        packet_time = packet.time
        sip_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'method': None,
            'from': None,
            'to': None,
            'headers': None,
            'body': None,
            'summary': None,
            'time': packet_time,
            'arrival_time': None,
        }

        hex_content = binascii.hexlify(packet.load).decode('utf-8')
        arrival_time_match = re.search(r'Arrival Time: (.*?)[\r\n]', hex_content)
        if arrival_time_match:
            arrival_time_str = arrival_time_match.group(1)
            sip_info['arrival_time'] = datetime.strptime(arrival_time_str, '%b %d, %Y %H:%M:%S.%f').strftime('%Y-%m-%d %H:%M:%S')

        if 'UDP' in packet and packet['UDP'].dport == 5060:
            try:
                sip = packet['UDP']['Raw'].load.decode('utf-8')

                sip_info['method'] = sip.split(' ')[0]

                from_match = re.search(r'From:(.*?)\r\n', sip, re.IGNORECASE | re.DOTALL)
                to_match = re.search(r'To:(.*?)\r\n', sip, re.IGNORECASE | re.DOTALL)

                if from_match:
                    sip_info['from'] = from_match.group(1).strip()

                if to_match:
                    sip_info['to'] = to_match.group(1).strip()

                sip_headers, sip_body = sip.split('\r\n\r\n', 1)
                sip_info['headers'] = sip_headers
                sip_info['body'] = sip_body

                summary_parts = []
                if sip_info['method']:
                    summary_parts.append(f"Method: {sip_info['method']}")
                if sip_info['from']:
                    summary_parts.append(f"From: {sip_info['from']}")
                if sip_info['to']:
                    summary_parts.append(f"To: {sip_info['to']}")

                sip_info['summary'] = ", ".join(summary_parts)

            except Exception as e:
                print("Error while extracting SIP info:", e)

        for key, value in sip_info.items():
            if isinstance(value, Decimal):
                sip_info[key] = float(value)

        return sip_info

    def post(self, request):
        if 'pcap_file' not in request.FILES:
            return Response({'error': 'No PCAP file provided.'}, status=status.HTTP_400_BAD_REQUEST)

        pcap_file = request.FILES['pcap_file']
        packets = rdpcap(pcap_file)

        file_identifier = pcap_file.name

        data_list = []  # Créez une liste pour stocker les données de ce fichier

        for packet in packets:
            sip_info = self.extract_sip_info(packet)
            analyzed_packet = {
                'file_identifier': file_identifier,
                'sip_info': sip_info,
                'created_at': timezone.now()
            }

            data_list.append(analyzed_packet)

            # Vérifiez la taille de la liste et réduisez-la si nécessaire
            if len(data_list) > self.max_data_list_size:
                data_list.pop(0)  # Retirez le premier élément pour maintenir la taille maximale

        # Stockez cette liste dans le dictionnaire global
        self.file_analyzed_packets[file_identifier] = data_list

        return Response({'message': 'File uploaded and analyzed successfully.'}, status=status.HTTP_201_CREATED)

class AnalysisResultsAPI(APIView):
    def get(self, request):
        latest_file_identifier = max(UploadAndAnalyzePCAPView.file_analyzed_packets.keys(), default=None)

        if latest_file_identifier is not None:
            # Récupérez la liste de paquets SIP pour le dernier fichier téléchargé
            data_list = UploadAndAnalyzePCAPView.file_analyzed_packets.get(latest_file_identifier, [])
            # Retournez cette liste de paquets SIP
            return Response(data_list, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'No data available.'}, status=status.HTTP_404_NOT_FOUND)
