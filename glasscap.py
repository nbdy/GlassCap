from Libs import ArgumentParser
from Libs import ExitHandler
from Libs import FileCarver
from Libs import FileChecker
from Libs import FileExtractor
from Libs import PCapParser

ArgParser = ArgumentParser.Parser()
FileExt = FileExtractor.Extractor()
FileCheck = FileChecker.Checker()
Exit = ExitHandler.Handler()
PcapParser = PCapParser.Parser()
Filecrv = FileCarver.Carver()

#TODOBLOCK
#TODO: Banners
#TODO: URL crawler

def banner():
    print "Some cewl Banners here."


def main2(args):
    if args.verbose is True:
        print "[*] Carving Pictures."
    picture_count = Filecrv.ImageCarver(args)
    nude_count, other_count = FileCheck.NudeChecker(args)
    if args.verbose is True:
        print "\t[+] Carved %d Pictures." % (picture_count)
        print "[*] Carving Archived Files."
    zip_count = Filecrv.ArchiveCarver(args)
    if args.verbose is True:
        print "\t[+] Carved %d Archives." % (zip_count)
        print "[*] Carving executables."
    exe_count = Filecrv.ExeCarver(args)
    if args.verbose is True:
        print "\t[+] Carved %d executables." % (exe_count)
        print "[*] Carving PDF's"
    pdf_count = Filecrv.PDFCarver(args)
    if args.verbose is True:
        print "\t[+] Carved %d PDF's." % (pdf_count)
        print "[*] Carving all visited URL's and sorting them."
    #url_count = carve_urls(args)
    if args.verbose is True:
        #print "\t[+] Carved %d URL's."
        print "\n"
        print "-" * 30
    Exit.summary(args, picture_count, zip_count, exe_count, pdf_count, nude_count, other_count)


def main(args):
    banner()
    if args.verbose is True:
        print "[*] Checking if necessary Directory's exist."
    FileCheck.DirectoryChecker()
    if args.verbose is True:
        print "[*] All Directorys should be present now."
    if args.directory is not None:
        c = 0
        dir_pcaps = PcapParser.get_pcap_from_dir(args)
        for dir_pcap in dir_pcaps:
            c += 1
            print "[*]", (len(dir_pcaps) - c), "PCaps left."
            args.pcap = dir_pcap
            main2(args)
    else:
        main2(args)


if __name__ == '__main__':
    args = ArgParser.ArgumentGetter()
    ArgParser.ArgumentChecker(args)
    main(args)