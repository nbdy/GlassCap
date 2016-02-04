import argparse
import os
import sys


class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser()

    def ArgumentGetter(self):
        self.parser.add_argument('-d', '--directory', action='store',
                                 help='Analyze all Pcaps from that directory.')
        self.parser.add_argument('-p', '--pcap', action='store',
                                 help='Read from PCAP.')
        self.parser.add_argument('-v', '--verbose', action='store_true',
                                 help='Verbose Output')

        args = self.parser.parse_args()
        return args

    def ArgumentChecker(self, args):
        if args.directory is not None:
            if args.pcap is not None:
                sys.exit("\n[!] Only specify a PCap or a Directory.")
        if args.pcap is not None:
            if os.path.isfile(args.pcap) is False:
                sys.exit("\n[!] Please provide a valid Path to the PCAP.")
        if args.directory is not None:
            if os.path.exists(args.directory) is False:
                sys.exit("\n[!] The Path you entered seems to be wrong.")
