import zlib


class Extractor:
    def ArchiveExtraction(self, headers, http_payload):
        archive = None
        archive_type = None
        try:
            if "application/zip" in headers['Content-Type']:
                archive_type = headers['Content-Type'].split("/")[1]
                archive = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            archive = zlib.decompress(archive, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            archive = zlib.decompress(archive)
                except:
                    pass
            elif "application/x-rar-compressed" in headers['Content-Type']:
                archive_type = headers['Content-Type'].split("/")[1]
                archive = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            archive = zlib.decompress(archive, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            archive = zlib.decompress(archive)
                except:
                    pass
        except:
            return None, None
        return archive, archive_type

    def ExeExtraction(self, headers, http_payload):
        exe = None
        exe_type = None
        try:
            if "x-ms-dos-executable" in headers['Content-Type']:
                exe_type = headers['Content-Type'].split("/")[1]
                exe = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            exe = zlib.decompress(exe, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            exe = zlib.decompress(exe)
                except:
                    pass

            elif "application/x-msi" in headers['Content-Type']:
                exe_type = headers['Content-Type'].split("/")[1]
                exe = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            exe = zlib.decompress(exe, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            exe = zlib.decompress(exe)
                except:
                    pass
        except:
            return None, None
        return exe, exe_type

    def ImageExtraction(self, headers, http_payload):
        image = None
        image_type = None
        try:
            if "image" in headers['Content-Type']:
                image_type = headers['Content-Type'].split("/")[1]
                image = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            image = zlib.decompress(image)
                except:
                    pass
        except:
            return None, None
        return image, image_type

    def PDFExtraction(self, headers, http_payload):
        pdf = None
        pdf_type = None
        try:
            if "application/pdf" in headers['Content-Type']:
                pdf_type = headers['Content-Type'].split("/")[1]
                pdf = http_payload[http_payload.index("\r\n\r\n") + 4:]
                try:
                    if "Content-Encoding" in headers.keys():
                        if headers['Content-Encoding'] == "gzip":
                            pdf = zlib.decompress(pdf, 16 + zlib.MAX_WBITS)
                        elif headers['Content-Encoding'] == "deflate":
                            pdf = zlib.decompress(pdf)
                except:
                    pass
        except:
            return None, None
        return pdf, pdf_type
