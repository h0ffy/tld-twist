#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# by h0ffy // @JennyLab  
# tld-twist v0.1 (Public Domain)
#
# https://wwww.jennylab.net
# https://github.com/h0ffy
# https://github.com/JennyLab
# https://github.com/JennyLabForks


from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import socket
import time
from simple_colors import *
from tqdm import tqdm
from pyfiglet import Figlet
from .whois_servers import whois_server_dict as whois_servers
from .config import TIMEOUT, DEBUG, VERBOSE, MAX_THREADS

# pip install simple-colors tqdm terminal_banner








def is_domain_registered(domain):
    # Extract TLD from domain.
    parts = domain.split('.')
    if len(parts) < 2:
        raise ValueError("The domain is not include tld (example: 'jennylab.net').")
    tld = parts[-1].lower()
    # Select server WHOIS based on TLD.
    try:
        server = whois_servers.get(tld)
    except KeyError:
        print(f"Not exists server to his TLD: {tld}")
        return False  

    try:
        # Connect with WHOIS server (port 43).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((server, 43))
            s.setblocking(True)
            query = domain + "\r\n"
            s.send(query.encode())
            response = b""
            while True:
                data = s.recv(4096)
                if DEBUG == True:
                    print(f'\n#######################################################{data}\n#######################################################\n\n')
                if not data:
                    break
                response += data
        result = response.decode(errors="ignore")
        if ("No match for" in result) or ("NOT FOUND" in result) or ("No Data Found" in result):
            return False
        else:
            return True
    except socket.timeout:
        return(red(f"Timeout to connect: {server}"))
    except socket.error as e:
        return(red(f"Error socket: {e}"))
        return False
    except Exception as e:
        return(red(f"Error knoweledge: {e}"))
    finally:
        # Cerrar la conexión.
        s.close()
        #print(f"Conexión cerrada con el servidor WHOIS: {server}")
        pass



def check_domain(name, tld_extension, tld_whois):
    try:
        status = yellow("[REG]") if is_domain_registered(f"{name}.{tld_extension}") else cyan("[FREE]")
        if status == "[FREE]":
            return(f"{name}.{tld_extension}\t->\t({tld_whois})\t\t{status}")
        elif VERBOSE:
            return(f"{name}.{tld_extension}\t->\t({tld_whois})\t\t{status}")
    except Exception as e:
        return red(f"[ERROR] Error on {name}.{tld_extension}: {e}")



def proc_check_all_tld(name):
    # Usar ThreadPoolExecutor threading pool executo
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:  # max threads
        futures = [
            executor.submit(check_domain, name, tld_extension, tld_whois)
            for tld_extension, tld_whois in whois_servers.items()
        ]

        
        progress_bar = tqdm(
            as_completed(futures), 
            total=len(futures), 
            desc=f"Scanning {name}", 
            bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
            ncols=100
        )

        with open(output_file, "w") as f:
            for future in progress_bar:
                result = future.result()
                if result:
                    f.write(f'{result}\n')
                    if result == True:
                        tqdm.write(green(result))
                    else:
                        tqdm.write(yellow(result))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Using: python tld-twist.py <name>")
        print("Using: python tld-twist.py --tlds <name>")
        print
        sys.exit(1)

    name = sys.argv[1]
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"{name}_{timestamp}.txt"
    custom_fig = Figlet(font='banner3')
    print(custom_fig.renderText(cyan("JennyLab")))
    print(magenta('tld-twist v0.1'))





