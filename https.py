from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import BaseServer
import ssl
from xml.etree.ElementTree import Element, SubElement, tostring, ElementTree, fromstring
import time
from io import BytesIO
from threading import Thread
from urllib import request
import os
import dns.resolver

import logging
from ros_crypt import rosEncryptor, rosEncryptorResult

import hashlib

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('[%(levelname)s] %(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

sslctx = ssl.create_default_context()
sslctx.check_hostname = False
sslctx.verify_mode = ssl.CERT_NONE

class cachedResolver(dns.resolver.Resolver):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nameservers = ['1.1.1.1']
        self.cached = dict()
    
    def look(self, host: str):
        if host not in self.cached:
            try:
                self.cached[host] = self.resolve(host)[0].to_text()
            except dns.resolver.NXDOMAIN:
                return "127.0.0.1"
        return self.cached[host]

resolver = cachedResolver()

class rosSession():
    def __init__(self, platform: str, sessionTicket: str):
        self.sessionTicket = sessionTicket
        self.md5 = hashlib.md5(sessionTicket.encode('utf-8')).hexdigest()
        self.sessionKey = None
        self.encryptor = rosEncryptor(platform)
    
    def setSessionKey(self, sessionKey: str):
        self.sessionKey = sessionKey
        self.encryptor.set_sessionkey_base64(sessionKey)

class rosService():
    def __init__(self, platform: str):
        self.platform = platform
        self.sessions = {}
    
    def session(self, sessionTicket: str) -> rosSession:
        if sessionTicket not in self.sessions:
            self.sessions[sessionTicket] = rosSession(self.platform, sessionTicket)
        return self.sessions[sessionTicket]

    def remove_session(self, sessionTicket: str) -> None:
        del self.sessions[sessionTicket]

service = rosService('pc')

class S(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def dump(self, request_headers = None, request_body = None, response_headers = None, response_body = None):
        sessionTicket = self.headers.get("ros-SessionTicket", "")

        if sessionTicket == "":
            return 

        session = service.session(sessionTicket)

        has_security = False
        if "239" in self.headers.get("ros-SecurityFlags", ""):
            has_security = True
        if "ExchangeTicket" in self.path:
            try:
                root = fromstring(response_body)
                key = root.find('{CreateTicketResponse}SessionKey').text
            except:
                key = None
            if key:
                logger.info('Found SessionKey!\n')
                session.setSessionKey(key)

        host = self.headers.get("Host", "")
        path = "paths/" + session.md5 + "/" + host + "/" + ("https" if self.is_https else "http") + self.path

        if not os.path.exists(path): 
            os.makedirs(path)   

        with open(path + "/requestheaders", "w") as file:
            file.write(str(request_headers))

        if request_body:
            with open(path + "/requestbody", "wb") as binary_file:
                binary_file.write((session.encryptor.decrypt_cl(request_body, True).bytes() if has_security else request_body))

        with open(path + "/responseheaders", "w") as file:
            file.write(str(response_headers))

        with open(path + "/responsebody", "wb") as binary_file:
            binary_file.write((session.encryptor.decrypt_sv(response_body, True).bytes() if has_security else response_body))

    def proxy_response(self, request_type: str):
        host = self.headers.get("Host", "")

        self.is_https = (True if self.server.server_port == 443 else False)
        ros_address = ("https://" if self.is_https else "http://") + resolver.look(host) + self.path
        #logger.info("LOOKUP RESULT: %s", resolver.look(host))
        req = request.Request(method=request_type, url=ros_address, headers=self.headers, data=(self.post_data if request_type == "POST" else None))
        try:
            response = request.urlopen(req, context = (sslctx if self.is_https else None))
        except request.HTTPError as e:
            response = e
        response_body = response.read()
       
        if "chunked" in response.headers.get("Transfer-Encoding", ""):
            del response.headers["Transfer-Encoding"]
            response.headers["Content-Length"] = str(len(response_body))

        self.send_response_only(response.status)

        for header in response.headers:
            self.send_header(header, response.headers[header])
        self.end_headers()
        
        self.wfile.write(response_body)

        self.dump(self.headers, self.post_data if hasattr(self, 'post_data') else None, response.headers, response_body)
        #response.headers['Status'] = str(response.status)
        

    def do_GET(self):
        logger.info("GET request,\nPath: %s\nHeaders:\n%s", str(self.path), str(self.headers))
        self.proxy_response("GET")

    def do_POST(self):
        post_data = b""

        if "Content-Length" in self.headers:
            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length)
            post_data = body
        elif "chunked" in self.headers.get("Transfer-Encoding", ""):
            while True:
                line = self.rfile.readline().strip()
                chunk_length = int(line, 16)

                if chunk_length != 0:
                    chunk = self.rfile.read(chunk_length)
                    post_data = post_data + chunk

                # Each chunk is followed by an additional empty newline
                # that we have to consume.
                self.rfile.readline()

                # Finally, a chunk size of 0 is an end indication
                if chunk_length == 0:
                    break

        self.post_data = post_data

        logger.info("POST request,\nPath: %s\nHeaders:\n%s", str(self.path), str(self.headers))

        self.proxy_response("POST")

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(certfile='ca.crt', keyfile='./ca.key')
context.check_hostname = False
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

def init_server(https):
    if https:
        with HTTPServer(("", 443), S) as httpd:
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logger.info('Starting https...')
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            httpd.server_close()
            logger.info('Stopping https...')
    else: # https
        with HTTPServer(("", 80), S) as httpd:
            logger.info('Starting http...')
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            httpd.server_close()
            logger.info('Stopping http...')

    httpd.serve_forever()
    httpd.server_close()

Thread(target=init_server, args=(True, )).start()
Thread(target=init_server, args=(False, )).start()