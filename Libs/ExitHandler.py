import sys


class Handler:
    def signal_handler(self, signal, frame):
        print "\n[!] You pressed CTRL + C."
        sys.exit()

    def summary(self, args, picture_count, zip_count, exe_count, pdf_count, nude_count, other_count):
        print "\n\n\n"
        print "Summary:"
        print "\tPCap File:\t%s" % (args.pcap)
        print "\t----------"
        print "\tPictures:\t%d" % (picture_count)
        print "\t\tNude:\t%d" % (nude_count)
        print "\t\tOther:\t%d" % (other_count)
        # print "\tURL's:\t\t%d" % (url_count)
        print "\tArchives:\t%d" % (zip_count)
        print "\tExecutables:\t%d" % (exe_count)
        print "\tPDF's:\t\t%d" % (pdf_count)
        print "\n\n\n\n"
