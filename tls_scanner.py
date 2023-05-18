import argparse
import json
import socket
from unittest import result # for connecting
from colorama import init, Fore

from threading import Thread, Lock
from queue import Queue
from multiprocessing.pool import ThreadPool

import requests as req
from http.client import HTTPSConnection
import OpenSSL, ssl
import ipaddress
from icmplib import ping, SocketPermissionError

from datetime import datetime, timezone
import time

# Script version
VER = "0.1 202305"

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX
RED = Fore.RED

# thread queue
q = Queue()
print_lock = Lock()

results = {}

def doScan(host, port):
    """
    Scan a port on the global variable `host`
    """
    result = ""
    try:
        s = socket.socket()
        s.settimeout(2.0) # Set socket connection timeout for 2 sec
        s.connect((host, port))
    except:
        with print_lock:
            if DEBUG_MODE:
                print(f"{GRAY}{host} - Port {port} is closed  {RESET}", end='\r')
    else:
        with print_lock:
            print(f"{GREEN}{host} - Port {port} is open    {RESET}")

            if port in [80, 8080]:
                try:
                    resp = req.get(f"http://{host}")
                    head = req.head(f"http://{host}")
                except:
                    print(f"{RED}{host:15}:{port:5} HTTP GET response error http://{host[0:40]}   {RESET}")
                else:
                    print(f"{GREEN}>{'':20} URL http://{host}")
                    
                    print(f"{GREEN}>{'':20} HTTP GET STATUS {'':15}: {resp.status_code}    {RESET}")

                    if resp.status_code in [302]:
                        print(f"{GREEN}>{'':20} HTTP REDIRECT {'':15}: {resp.url}    {RESET}")

                    if 'server' in head.headers:
                        print(f"{GREEN}>{'':20} HTTP GET SERVER {'':15}: {head.headers['server']}    {RESET}")
                    if 'content-type' in head.headers:
                        print(f"{GREEN}>{'':20} HTTP GET CONTENT-TYPE {'':9}: {head.headers['content-type']}    {RESET}")

            if port in [443, 8443]:
                if DEBUG_MODE:
                    print(f"{GRAY}{host}:{port} - Expecting TLS {str(tls_expected)}")     #, dir(conn))

                for tls_version in [1.0, 1.1, 1.2, 1.3]: # 1.3 not supported yet?
                    try:
                        tls_check(host, port, tls_version)
                    except:
                        print(f"{RED}{host}:{port} - TLS CHECK {tls_version} ERROR {RESET}")

    finally:
        s.close()
    
    return result


def tls_check(host, port, tls_version):
    
    sock_pair = (host, port)

    # context = ssl.create_default_context()
    # context.verify_mode = ssl.CERT_REQUIRED
    # context.check_hostname = True
    # context.load_default_certs()

    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ssl_sock = context.wrap_socket(s, server_hostname=host)
    # try:
    #     ssl_sock.connect((host, 443))
    #     print(f"{GREEN}{host}:{port} - Successful {ssl_sock.version()} as default")
    # except:
    #     print(f"{RED}{host}:{port} - TLS CHECK {tls_version} FAILED")

    # https://docs.python.org/3/library/ssl.html#ssl.SSLContext
    sslCntx = ssl.create_default_context()  
    sslCntx.options &= ssl.OP_NO_SSLv2
    sslCntx.options &= ssl.OP_NO_SSLv3
    if tls_version:
        if tls_version == 1.1:
            sslCntx.options &= ssl.OP_NO_TLSv1
        if tls_version == 1.2:
            sslCntx.options &= ssl.OP_NO_TLSv1_1
        if tls_version == 1.3:
            sslCntx.options &= ssl.OP_NO_TLSv1_2
    
    # sslCntx.load_cert_chain(*ssl_files_def)

    # print('TLS version:', int(ssl.PROTOCOL_TLSv1), int(ssl.PROTOCOL_TLSv1_1), int(ssl.PROTOCOL_TLSv1_2)) #, ssl.PROTOCOL_TLSv1_3)
    # print('Scan context:', sslCntx.options, int(sslCntx.minimum_version), int(sslCntx.maximum_version), sslCntx.verify_flags, sslCntx.verify_mode, sslCntx.get_ca_certs()) #, sslCntx.get_ciphers(), dir(sslCntx))

    try:
        conn = HTTPSConnection(*sock_pair, context=sslCntx)
        if DEBUG_MODE:
            print(f"{GRAY}{host}:{port} - TLS {str(tls_version)} check initiated")     #, dir(conn))
        # connection failures -> EXCEPT
        conn.request( 'GET', '/' )
        ans = conn.getresponse()
        print(f"{GREEN}{host}:{port} - Successful TLS {str(tls_version)} connection {RESET}")

        if DEBUG_MODE and tls_version == float(tls_expected):
            print(f"{GRAY}============== HTTP HEADERS =================")
            print(f"{GRAY}GET {ans.reason}: {ans.status}")
            print(f"{GRAY}{ans.headers}")
            print(f"{GRAY}=============================================")
        
        # Attempt to fetch the crtificate for the specifed TLS version only
        if tls_version == float(tls_expected):
            try:
                cert_check(host, port, sslCntx)
            except:
                print(f"{RED}{host:15}:{port:5}: Failed to fetch certificate {RESET}")
        
        conn.close()
    except:
        if tls_version == float(tls_expected) or DEBUG_MODE:
            print(f"{RED}{host:15}:{port:10}: Failed to connect with TLS {str(tls_version)} {RESET}")

def cert_check(host, port, sslCntx):
    try:
        if DEBUG_MODE:
            print(f"{GRAY}{host:15}:{port:10}: Certificate check initiated")
        
        with socket.create_connection((host, port)) as sock:
            with sslCntx.wrap_socket(sock, server_hostname = host) as ssock:
                certificate = ssock.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(certificate)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        # Check certificate expiry
        expiry_date = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
        if datetime.now(timezone.utc) > expiry_date:
            print(f"{RED}{host:15}:{port:10}: Certificate is expired {expiry_date} {RESET}")
        elif DEBUG_MODE:
            print(f"{GRAY}{host:15}:{port:10}: Certificate expires {expiry_date}")
    except:
        print(f"{RED}{host:15}:{port:10}: Failed to get server certificate {RESET}")

def scan_thread():
    i = 0
    donePing = False
    while not q.empty():
        # Get the target and port number from the queue
        (target, port) = q.get()

        # If we're testing for Ping then attempt it and clear the queue if target is down.
        if doPing and donePing == False:
            try:
                pingTest = ping(target,count=1,interval=1)
                donePing = True
                if pingTest.is_alive == False:
                    with q.mutex:
                        q.clear()
            except SocketPermissionError as err:
                with q.mutex:
                    q.queue.clear()
                print(err)
        
        # We might have just emptied the queue based on the ping test, so check again.
        if not q.empty():
            result = doScan(target, port)
            print_lock.acquire()
            results[port] = result
            print_lock.release()
            # tells the queue that the scanning for that port is done
            q.task_done()
            i = i + 1


def thread_init(target, port):
    q.put((target, port))

    for t in range(N_THREADS):
        # for each thread, start it
        t = Thread(target=scan_thread, args=())
        # when we set daemon to true, that thread will end when the main thread ends
        t.daemon = True
        # start the daemon thread
        t.start()

    
    # wait the threads ( port scanners ) to finish
    q.join()


if __name__ == "__main__":
    # Parse the input parameters
    parser = argparse.ArgumentParser(description="SSL/TLS scanner and response analyzer")
    parser.add_argument("--host", "-host", dest="host", default="", help="Host name to scan.")
    parser.add_argument("--port", "-p", dest="port", default="443", help="Port to scan, default is 1-1023 (low ports)")
    parser.add_argument("--ping", "-ping", dest="ping", default=False, action="store_true", help="Ping the target with one packet before attempting a port scan. Requires ICMP response.")
    parser.add_argument("--tls_ver", "-tls", dest="tls_ver", default=1.2, help="The TLS version expected for any TLS connections.")
    parser.add_argument("--threads", "-t", dest="threads", default="100", help="Number of threads to create for scanning work.")
    parser.add_argument("--output", "-o", dest="output", default="stdout", help="Output results to stdout, csv, json.")
    parser.add_argument("--debug", "-d", dest="debug", default=False, action="store_true", help="Enable debug option for more verbosity.")
    
    args = parser.parse_args()
    target, port, doPing = args.host, int(args.port), args.ping

    if port not in range(1,65535):
        raise parser.error('Port argument must be between 1 and 65535 and either single value or a range. e.g. -p 80, -p 1-1023')

    tls_expected = args.tls_ver

    # number of threads, defaulted to 100 as per argparse
    N_THREADS = int(args.threads)

    # Debug mode
    DEBUG_MODE = args.debug

    print(f"{GRAY} TLS Scanner by lurch v{VER}")
    if DEBUG_MODE:
        print(f" ** DEBUG_MODE is {args.debug} **")
        print(f" -- Local host supported TLS versions")
        print(f" -- {'':20} SSLv2/3{'':4}: {ssl.PROTOCOL_SSLv23}")
        print(f" -- {'':20} TLSv1{'':6}: {ssl.HAS_TLSv1}")
        print(f" -- {'':20} TLSv1.1{'':4}: {ssl.HAS_TLSv1_1}")
        print(f" -- {'':20} TLSv1.2{'':4}: {ssl.HAS_TLSv1_2}")
        print(f" -- {'':20} TLSv1.3{'':4}: {ssl.HAS_TLSv1_3}")

    t0 = time.perf_counter()
    print(f" -- Scanning start time {time.strftime('%H:%M:%S', time.localtime())} {RESET}")

    # Kick off the threads and scan the host
    # thread_init(target, port)
    doScan(target, port)

    print(json.dumps(results, indent=4))

    t1 = time.perf_counter()
    print(f"{GRAY} -- Scanning end time {time.strftime('%H:%M:%S', time.localtime())}")
    print(f" -- Scanning duration {(t1 - t0)} sec {RESET}")
