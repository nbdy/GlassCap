import os
import re
import sys
import zlib
import nude
import signal
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Suppress Scapy IPv6 Warning
import argparse
from scapy.all import *
from time import sleep


#TODOBLOCK
#TODO: Banners
#TODO: URL crawler

parser = argparse.ArgumentParser()

parser.add_argument('-d', '--directory', action='store',
                    help='Analyze all Pcaps from that directory.')
parser.add_argument('-p', '--pcap', action='store',
                    help='Read from PCAP.')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Verbose Output')

args = parser.parse_args()

if args.directory is not None:
    if args.pcap is not None:
        sys.exit("\n[!] Only specify a PCap or a Directory.")
if args.pcap is not None:
    if os.path.isfile(args.pcap) is False:
        sys.exit("\n[!] Please provide a valid Path to the PCAP.")
if args.directory is not None:
    if os.path.exists(args.directory) is False:
        sys.exit("\n[!] The Path you entered seems to be wrong.")


def signal_handler(signal, frame):
    print "\n[!] You pressed CTRL + C."
    sys.exit()

signal.signal(signal.SIGINT, signal_handler)


#Check if Dirs exist, else create them.
def check_dirs():
    if os.path.exists('./carved_content') is False:
        os.makedirs('./carved_content')
    if os.path.exists('./carved_content/pictures') is False:
        os.makedirs('./carved_content/pictures')
    if os.path.exists('./carved_content/pictures/nude') is False:
        os.makedirs('./carved_content/pictures/nude')
    if os.path.exists('./carved_content/pictures/other') is False:
        os.makedirs('./carved_content/pictures/other')
    if os.path.exists('./carved_content/archives') is False:
        os.makedirs('./carved_content/archives')
    if os.path.exists('./carved_content/urls') is False:
        os.makedirs('./carved_content/urls')
    if os.path.exists('./carved_content/exe') is False:
        os.makedirs('./carved_content/exe')
    if os.path.exists('./carved_content/pdf') is False:
        os.makedirs('./carved_content/pdf')


def extract_image(headers, http_payload):
    image = None
    image_type = None
    try:
        if "image" in headers['Content-Type']:
            image_type = headers['Content-Type'].split("/")[1]
            image = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None,None
    return image,image_type


#Get Headers of reassembled Stream and check if 'Content-Type' is present.
def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
    except:
        return None

    if "Content-Type" not in headers:
        return None

    return headers


def check_nude(args):
    nude_counter = 0
    other_counter = 0
    picture_path = './carved_content/pictures/'
    nude_path = './carved_content/pictures/nude/'
    pictures = []
    temp_pictures = [f for f in os.listdir(picture_path) if os.path.isfile(os.path.join(picture_path, f))]
    for temp_picture in temp_pictures:
        if temp_picture.endswith('.jpg') or temp_picture.endswith('.jpeg'):
            temp_picture = picture_path + temp_picture
            pictures.append(temp_picture)
    for picture in pictures:
        try:
            if nude.is_nude(picture) is True:
                tmp_picture = string.split(picture, '/')[-1]
                tmp_picture = nude_path + tmp_picture
                os.rename(picture, tmp_picture)
                nude_counter += 1
            else:
                other_counter += 1
        except:
            pass
    return nude_counter, other_counter



def carve_pictures(args):
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
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            file_name = "%s_%d.%s" % (temp_pcap_name, images, image_type)
            f = open("%s%s" % (picture_directory,file_name), "wb")
            f.write(image)
            f.close()
            images += 1

    return images


def extract_archive(headers, http_payload):
    archive = None
    archive_type = None
    try:
        if "application/zip" in headers['Content-Type']:
            archive_type = headers['Content-Type'].split("/")[1]
            archive = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        archive = zlib.decompress(archive, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        archive = zlib.decompress(archive)
            except:
                pass
        elif "application/x-rar-compressed" in headers['Content-Type']:
            archive_type = headers['Content-Type'].split("/")[1]
            archive = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        archive = zlib.decompress(archive, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        archive = zlib.decompress(archive)
            except:
                pass
    except:
        return None, None
    return archive, archive_type


def extract_exe(headers, http_payload):
    exe = None
    exe_type = None
    try:
        if "x-ms-dos-executable" in headers['Content-Type']:
            exe_type = headers['Content-Type'].split("/")[1]
            exe = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        exe = zlib.decompress(exe, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        exe = zlib.decompress(exe)
            except:
                pass

        elif "application/x-msi" in headers['Content-Type']:
            exe_type = headers['Content-Type'].split("/")[1]
            exe = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        exe = zlib.decompress(exe, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        exe = zlib.decompress(exe)
            except:
                pass
    except:
        return None,None
    return exe, exe_type


def carve_exe(args):
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
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        exe, exe_type = extract_exe(headers, http_payload)
        if exe is not None and exe_type is not None:
            file_name = "%s_%d.%s" % (temp_pcap_name, exes, exe_type)
            f = open("%s%s" % (exe_directory,file_name), "wb")
            f.write(exe)
            f.close()
            exes += 1
    return exes


def carve_archives(args):
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
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        archive, archive_type = extract_archive(headers, http_payload)
        if archive is not None and archive_type is not None:
            file_name = "%s_%d.%s" % (temp_pcap_name, archives, archive_type)
            f = open("%s%s" % (archive_directory,file_name), "wb")
            f.write(archive)
            f.close()
            archives += 1
    return archives


def summary(args, picture_count, zip_count, exe_count, pdf_count, nude_count, other_count):
    print "\n\n\n"
    print "Summary:"
    print "\tPCap File:\t%s" % (args.pcap)
    print "\t----------"
    print "\tPictures:\t%d" % (picture_count)
    print "\t\tNude:\t%d" % (nude_count)
    print "\t\tOther:\t%d" % (other_count)
    #print "\tURL's:\t\t%d" % (url_count)
    print "\tArchives:\t%d" % (zip_count)
    print "\tExecutables:\t%d" % (exe_count)
    print "\tPDF's:\t\t%d" % (pdf_count)
    print "\n\n\n\n"


def carve_urls(args):
    sqli = searchengine = porn = social = 0
    p = rdpcap(args.pcap)
    return 1


def extract_pdf(headers, http_payload):
    pdf = None
    pdf_type = None
    try:
        if "application/pdf" in headers['Content-Type']:
            pdf_type = headers['Content-Type'].split("/")[1]
            pdf = http_payload[http_payload.index("\r\n\r\n")+4:]
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        pdf = zlib.decompress(pdf, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] =="deflate":
                        pdf = zlib.decompress(pdf)
            except:
                pass
    except:
        return None,None
    return pdf, pdf_type


def carve_pdf(args):
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
        headers = get_http_headers(http_payload)
        if headers is None:
            continue
        pdf, pdf_type = extract_pdf(headers, http_payload)
        if pdf is not None and pdf_type is not None:
            file_name = "%s_%d.%s" % (temp_pcap_name, pdfs, pdf_type)
            f = open("%s%s" % (pdf_directory,file_name), "wb")
            f.write(pdf)
            f.close()
            pdfs += 1
    return pdfs


def banner():
    print "Some cewl Banners here."


def main2(args):
    if args.verbose is True:
        print "[*] Carving Pictures."
    picture_count = carve_pictures(args)
    nude_count, other_count = check_nude(args)
    if args.verbose is True:
        print "\t[+] Carved %d Pictures." % (picture_count)
        print "[*] Carving Archived Files."
    zip_count = carve_archives(args)
    if args.verbose is True:
        print "\t[+] Carved %d Archives." % (zip_count)
        print "[*] Carving executables."
    exe_count = carve_exe(args)
    if args.verbose is True:
        print "\t[+] Carved %d executables." % (exe_count)
        print "[*] Carving PDF's"
    pdf_count = carve_pdf(args)
    if args.verbose is True:
        print "\t[+] Carved %d PDF's." % (pdf_count)
        print "[*] Carving all visited URL's and sorting them."
    #url_count = carve_urls(args)
    if args.verbose is True:
        #print "\t[+] Carved %d URL's."
        print "\n"
        print "-" * 30
    summary(args, picture_count, zip_count, exe_count, pdf_count, nude_count, other_count)


def get_pcap_from_dir(args):
    temp_dir_pcaps = []
    dir_pcaps = []
    temp_dir_pcaps = [f for f in os.listdir(args.directory) if os.path.isfile(os.path.join(args.directory, f))]
    for temp_dir_pcap in temp_dir_pcaps:
        if args.directory.endswith('/'):
            temp_dir_pcap = args.directory + temp_dir_pcap
        else:
            temp_dir_pcap = args.directory + '/' + temp_dir_pcap
        dir_pcaps.append(temp_dir_pcap)
    if not dir_pcaps:
        sys.exit("\n[!] Was not able to find any PCaps in that directory.")
    if args.verbose is True:
        print "[*] Found", len(dir_pcaps), "in that Directory."
    return dir_pcaps


def main(args):
    banner()
    if args.verbose is True:
        print "[*] Checking if necessary Directory's exist."
    check_dirs()
    if args.verbose is True:
        print "[*] All Directorys should be present now."
    if args.directory is not None:
        c = 0
        dir_pcaps = get_pcap_from_dir(args)
        for dir_pcap in dir_pcaps:
            c += 1
            print "[*]", (len(dir_pcaps) - c), "PCaps left."
            args.pcap = dir_pcap
            main2(args)
    else:
        main2(args)



if __name__ == '__main__':
    main(args)