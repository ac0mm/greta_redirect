# greta_redirect

Greta_redirect is a program that assists with uploading, downloading, and redirecting from a target.

## Description

Greta is targeted to help penetration testers upload and download files from a target and redirect through a target.

Demo: <link>

## Table of Contents

  - Requirements
  - Installation
  - Use
  - Three Main Points
  - Why I am interested
  - Areas of Improvement

## Requirements
  - A Linux O/S capable of running Greta
  - python3 ( Tested on python 3.9.2)
  - root permissions (required for UDP traffic)
  - ssl certificate and key
  - Directories called "logs", "upload", "http", and "downloads" in the same directory as greta_recdirect is running out of
  - socat or netcat on target

## Installation

Note: Use sudo where necessary

1. Clone the repository

   git clone https://github.com/ac0mm/greta_redirect.git

2. Change into the greta directory

3. Make a logs directory

     mkdir logs upload http downloads certs

4. Generate Certificates

    Example Command:
       openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out example.crt -keyout example.key
          
5. Installed!

## Use

  python3 greta_server.py -h

  usage: 
  
    greta_redirect.py version 0.5 [-h] [-i] [-l HOST] [-p PORT] [-r REDIRECT_TYPE] [-t PROTO_TYPE] [--direction DIRECTION] [--tun_listen_port TUN_LISTEN_PORT] [--target_port TARGET_PORT] [--target_ip TARGET_IP] [-u UPFILE] [-d DOWNFILE] [-f FILE_DEST] [-o OSTYPE] [-b CALLBACK] [-c CERTFILE]
                                     [-k KEYFILE]

  options:
  
    -h, --help            show this help message and exit
    
    -i, --interactive     This option walks through an interactive menu to set values and will ignore any other options
    
    -l HOST, --host HOST  Set host for listener to bind to
    
    -p PORT, --port PORT  Set port for listner to bind to
    
    -r REDIRECT_TYPE, --redirect_type REDIRECT_TYPE
    
                          Pick the redirection type you want: upload download tunnel
    -t PROTO_TYPE, --proto_type PROTO_TYPE
                          Pick the protocol type: upload: tcp udp tls https http Download: tcp udp tls redirect: tcp udp
    --direction DIRECTION
                          Pick forward or reverse tunnel
    --tun_listen_port TUN_LISTEN_PORT
                          Tunnel to bind on, for forward this will be on your device, for reverse this will be on the target
    --target_port TARGET_PORT
                          Port that tunnel will send traffic to
    --target_ip TARGET_IP
                          Target ip you want to bend your traffic to
    -u UPFILE, --upfile UPFILE
                          File you wish to upload, for http and https please ensure they are in a folder called http
    -d DOWNFILE, --downfile DOWNFILE
                          File you wish to download
    -f FILE_DEST, --file_dest FILE_DEST
                          This is where you want to save the file to (upload would be on target, download will be on your host)
    -o OSTYPE, --ostype OSTYPE
                          The type of OS you will be interacting from: linux windows
    -b CALLBACK, --callback CALLBACK
                          Callback IP:PORT (192.168.1.1:1234)
    -c CERTFILE, --certfile CERTFILE
                          Set the TLS certificate file
    -k KEYFILE, --keyfile KEYFILE
                          Set the TLS key file

  Routes? Where we are going we don't need routes


## Three Main Points
  - Provide a means to transfer files
  - Provide a means to redirect from a target
  - Offer encrypted and unencrypted means

## Why I am Interested

As a stepping stone to integrating with the C2 framework I am building, greta, I have built a standalone tool that simplifies file transfers and redirecting through a target. When a penetration tester is conducting a test, they will commonly need to transfer files or redirect from a target. With greta_redirect, I provide the means to upload and download files using a few different techniques and allows redirecting through a target using TCP or UDP. The redirection is TLS wrapped through socat and openssl. This gives the tester a quick way to get files to and from the target and redirect to targets that might not be accessible to them normally.

## Areas of Improvement

- Better error handling
- UDP downloads that work
- Windows pastable commands for file transfer and redirecting
- openssl upload and download lines
