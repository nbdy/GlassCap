import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress Scapy IPv6 Warning
from scapy.all import *
from scapy_http import http
import PCapParser
import FileExtractor

PcapParser = PCapParser.Parser()
FileExt = FileExtractor.Extractor()

class Carver:
    def ExeCarver(self, args):
        exe_directory = './carved_content/exe/'
        temp_pcap_name = string.split(args.pcap, '/')[-1]
        exes = 0
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            http_payload = ''
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload += str(packet[TCP].payload)
                except:
                    pass
            headers = PcapParser.get_http_headers(http_payload)
            if headers is None:
                continue
            exe, exe_type = FileExt.ExeExtraction(headers, http_payload)
            if exe is not None and exe_type is not None:
                file_name = "%s_%d.%s" % (temp_pcap_name, exes, exe_type)
                f = open("%s%s" % (exe_directory, file_name), "wb")
                f.write(exe)
                f.close()
                exes += 1
        return exes

    def ImageCarver(self, args):
        picture_directory = './carved_content/pictures/'
        temp_pcap_name = string.split(args.pcap, '/')[-1]
        images = 0
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            http_payload = ''
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload += str(packet[TCP].payload)
                except:
                    pass
            headers = PcapParser.get_http_headers(http_payload)
            if headers is None:
                continue
            image, image_type = FileExt.ImageExtraction(headers, http_payload)
            if image is not None and image_type is not None:
                file_name = "%s_%d.%s" % (temp_pcap_name, images, image_type)
                f = open("%s%s" % (picture_directory, file_name), "wb")
                f.write(image)
                f.close()
                images += 1

        return images

    def ArchiveCarver(args):
        archive_directory = './carved_content/archives/'
        temp_pcap_name = string.split(args.pcap, '/')[-1]
        archives = 0
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            http_payload = ''
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload += str(packet[TCP].payload)
                except:
                    pass
            headers = PcapParser.get_http_headers(http_payload)
            if headers is None:
                continue
            archive, archive_type = FileExt.ArchiveExtraction(headers, http_payload)
            if archive is not None and archive_type is not None:
                file_name = "%s_%d.%s" % (temp_pcap_name, archives, archive_type)
                f = open("%s%s" % (archive_directory, file_name), "wb")
                f.write(archive)
                f.close()
                archives += 1
        return archives

    def PDFCarver(self, args):
        pdf_directory = './carved_content/pdf/'
        temp_pcap_name = string.split(args.pcap, '/')[-1]
        pdfs = 0
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            http_payload = ''
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload += str(packet[TCP].payload)
                except:
                    pass
            headers = PcapParser.get_http_headers(http_payload)
            if headers is None:
                continue
            pdf, pdf_type = FileExt.PDFExtraction(headers, http_payload)
            if pdf is not None and pdf_type is not None:
                file_name = "%s_%d.%s" % (temp_pcap_name, pdfs, pdf_type)
                f = open("%s%s" % (pdf_directory, file_name), "wb")
                f.write(pdf)
                f.close()
                pdfs += 1
        return pdfs

    def URLCarver(self, args):
        url_directory = './carved_content/urls/'
        temp_pcap_name = string.split(args.pcap, '/')[-1]
        urls = 0
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            for pkt in sessions[session]:
                if not pkt.haslayer(http.HTTPRequest):
                    return 0
                else:
                    http_layer = pkt.getlayer(http.HTTPRequest)
                    ip_layer = pkt.getlayer(IP)
                    filename = "%s.txt" % (temp_pcap_name)
                    f = open("%s%s" % (url_directory, filename), 'a')
                    f.write("%s>>>%s" % (http_layer, ip_layer))
                    f.close()
                    urls += 1

        return urls

    # TODO: SessionWorker to shorten everything down a bit
    """
    def SessionWorker(self, args):
        p = rdpcap(args.pcap)
        sessions = p.sessions()
        for session in sessions:
            http_payload = ''
            for pkt in sessions[session]:
    """
