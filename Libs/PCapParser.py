import os
import re
import sys


# TODO: If Pcap dir is chosen only print a summary at the end of the analysation

class Parser:
    def get_http_headers(self, http_payload):
        try:
            headers_raw = http_payload[:http_payload.index("\r\n\r\n") + 2]
            headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
        except:
            return None

        if "Content-Type" not in headers:
            return None

        return headers

    def get_pcap_from_dir(self, args):
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
