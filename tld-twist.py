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


# pip install simple-colors tqdm terminal_banner


TIMEOUT=10
DEBUG=False
VERBOSE=True
MAX_THREADS=25




# Diccionario de TLD a servidor WHOIS.
whois_servers = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.info',
    'biz': 'whois.biz',
    'co': 'whois.nic.co',
    'io': 'whois.nic.io',
    'me': 'whois.nic.me',
    'cc': 'whois.nic.cc',
    "ac": "whois.nic.ac",
    "ad": "whois.ripe.net",
    "ae": "whois.aeda.net.ae",
    "aero": "whois.aero",
    "af": "whois.nic.af",
    "ag": "whois.nic.ag",
    "al": "whois.nic.al",
    "am": "whois.amnic.net",
    "arpa": "whois.iana.org",
    "as": "whois.nic.as",
    "asia": "whois.nic.asia",
    "at": "whois.nic.at",
    "au": "whois.audns.net.au",
    "aw": "whois.nic.aw",
    "ax": "whois.ax",
    "az": "whois.afilias.net",
    "ba": "whois.nic.ba",
    "bb": "whois.nic.bb",
    "bd": "whois.bd",
    "be": "whois.dns.be",
    "bf": "whois.onatel.bf",
    "bg": "whois.register.bg",
    "bh": "whois.bh",
    "bi": "whois.nic.bi",
    "biz": "whois.biz",
    "bj": "whois.nic.bj",
    "bm": "whois.bm",
    "bn": "whois.bn",
    "bo": "whois.nic.bo",
    "br": "whois.registro.br",
    "bs": "whois.registerbs.com",
    "bt": "whois.nic.bt",
    "bv": "whois.norid.no",  # Aproximado; algunos TLD especiales se derivan de Norid
    "bw": "whois.nic.net.bw",
    "by": "whois.ripe.net",
    "bz": "whois.belizenic.bz",
    "ca": "whois.cira.ca",
    "cat": "whois.domini.cat",
    "cc": "whois.nic.cc",
    "cd": "whois.cd",
    "cf": "whois.nic.cf",
    "cg": "whois.nic.cg",
    "ch": "whois.nic.ch",
    "ci": "whois.nic.ci",
    "ck": "whois.nic.ck",
    "cl": "whois.nic.cl",
    "cm": "whois.net.cm",
    "cn": "whois.cnnic.cn",
    "co": "whois.nic.co",
    "com": "whois.verisign-grs.com",
    "coop": "whois.nic.coop",
    "cr": "whois.nic.cr",
    "cu": "whois.nic.cu",
    "cv": "whois.cv",
    "cw": "whois.nic.cw",
    "cx": "whois.nic.cx",
    "cy": "whois.nic.cy",
    "cz": "whois.nic.cz",
    "de": "whois.denic.de",
    "dj": "whois.dj",
    "dk": "whois.dk-hostmaster.dk",
    "dm": "whois.nic.dm",
    "do": "whois.nic.do",
    "dz": "whois.nic.dz",
    "ec": "whois.nic.ec",
    "edu": "whois.educause.edu",
    "ee": "whois.eenet.ee",
    "eg": "whois.eg",
    "eh": "whois.ripe.net",  # No oficial; aproximado
    "er": "whois.er",
    "es": "whois.nic.es",
    "et": "whois.telecom.net.et",
    "eu": "whois.eu",
    "fi": "whois.ficora.fi",
    "fj": "whois.fj",
    "fk": "whois.fidc.co.fk",
    "fm": "whois.dot.fm",
    "fo": "whois.nic.fo",
    "fr": "whois.nic.fr",
    "ga": "whois.ga",
    "gb": "whois.nic.uk",  # gb está obsoleto; se utiliza uk
    "gd": "whois.adamsnames.com",
    "ge": "whois.ge",
    "gf": "whois.nplus.gf",
    "gg": "whois.gg",
    "gh": "whois.ghana",
    "gi": "whois2.afilias-grs.net",
    "gl": "whois.nic.gl",
    "gm": "whois.nic.gm",
    "gn": "whois.nic.gn",
    "gp": "whois.nic.gp",
    "gq": "whois.gq",
    "gr": "whois.gr",
    "gs": "whois.nic.gs",
    "gt": "whois.gt",
    "gu": "whois.gu",
    "gw": "whois.register.gw",
    "gy": "whois.registry.gy",
    "hk": "whois.hkirc.hk",
    "hm": "whois.registry.hm",
    "hn": "whois.nic.hn",
    "hr": "whois.dns.hr",
    "ht": "whois.nic.ht",
    "hu": "whois.nic.hu",
    "id": "whois.pandi.or.id",
    "ie": "whois.domainregistry.ie",
    "il": "whois.isoc.org.il",
    "im": "whois.nic.im",
    "in": "whois.inregistry.net",
    "info": "whois.afilias.net",
    "int": "whois.iana.org",
    "io": "whois.nic.io",
    "iq": "whois.nic.iq",
    "ir": "whois.nic.ir",
    "is": "whois.isnic.is",
    "it": "whois.nic.it",
    "je": "whois.je",
    "jm": "whois.jm",
    "jo": "whois.jo",
    "jobs": "whois.verisign-grs.com",
    "jp": "whois.jprs.jp",
    "ke": "whois.kenic.or.ke",
    "kg": "whois.domain.kg",
    "kh": "whois.nic.kh",
    "ki": "whois.nic.ki",
    "km": "whois.nic.km",
    "kn": "whois.nic.kn",
    "kp": "whois.kcce.kp",
    "kr": "whois.nic.or.kr",
    "kw": "whois.kw",
    "ky": "whois.nic.ky",
    "kz": "whois.nic.kz",
    "la": "whois.nic.la",
    "lb": "whois.aub.edu.lb",
    "lc": "whois.nic.lc",
    "li": "whois.nic.li",
    "lk": "whois.nic.lk",
    "lr": "whois.psg.com",
    "ls": "whois.ls",
    "lt": "whois.domreg.lt",
    "lu": "whois.dns.lu",
    "lv": "whois.nic.lv",
    "ly": "whois.nic.ly",
    "ma": "whois.nic.ma",
    "mc": "whois.nic.mc",
    "md": "whois.nic.md",
    "me": "whois.nic.me",
    "mg": "whois.nic.mg",
    "mh": "whois.nic.net.mh",
    "mil": "whois.nic.mil",
    "mk": "whois.mpt.com.mk",
    "ml": "whois.sotelma.ml",
    "mm": "whois.nic.mm",
    "mn": "whois.nic.mn",
    "mo": "whois.monic.net.mo",
    "mobi": "whois.dotmobiregistry.net",
    "mp": "whois.nic.mp",
    "mq": "whois.nic.mq",
    "mr": "whois.nic.mr",
    "ms": "whois.nic.ms",
    "mt": "whois.nic.mt",
    "mu": "whois.nic.mu",
    "museum": "whois.museum",
    "mv": "whois.nic.mv",
    "mw": "whois.nic.mw",
    "mx": "whois.nic.mx",
    "my": "whois.mynic.net.my",
    "mz": "whois.nic.mz",
    "na": "whois.na-nic.com.na",
    "name": "whois.nic.name",
    "nc": "whois.nc",
    "ne": "whois.ne",
    "net": "whois.verisign-grs.com",
    "nf": "whois.nic.nf",
    "ng": "whois.nic.net.ng",
    "ni": "whois.nic.ni",
    "nl": "whois.domain-registry.nl",
    "no": "whois.norid.no",
    "np": "whois.mos.com.np",
    "nr": "whois.nr",
    "nu": "whois.nic.nu",
    "nz": "whois.srs.net.nz",
    "om": "whois.om",
    "org": "whois.pir.org",
    "pa": "whois.nic.pa",
    "pe": "whois.nic.pe",
    "pf": "whois.pf",
    "pg": "whois.nic.pg",
    "ph": "whois.domains.ph",
    "pk": "whois.pknic.net.pk",
    "pl": "whois.dns.pl",
    "pm": "whois.nic.pm",
    "pn": "whois.nic.pn",
    "pr": "whois.nic.pr",
    "pro": "whois.registrypro.pro",
    "ps": "whois.ps",
    "pt": "whois.dns.pt",
    "pw": "whois.nic.pw",
    "py": "whois.nic.py",
    "qa": "whois.qatar.net.qa",
    "re": "whois.nic.re",
    "ro": "whois.rotld.ro",
    "rs": "whois.rnids.rs",
    "ru": "whois.ripn.net",
    "rw": "whois.ricta.org.rw",
    "sa": "whois.nic.net.sa",
    "sb": "whois.nic.net.sb",
    "sc": "whois2.afilias-grs.net",
    "sd": "whois.sd",
    "se": "whois.iis.se",
    "sg": "whois.nic.net.sg",
    "sh": "whois.nic.sh",
    "si": "whois.arnes.si",
    "sj": "whois.norid.no",
    "sk": "whois.sk-nic.sk",
    "sl": "whois.nic.sl",
    "sm": "whois.ripe.net",
    "sn": "whois.nic.sn",
    "so": "whois.nic.so",
    "sr": "whois.sr",
    "st": "whois.nic.st",
    "su": "whois.ripn.net",
    "sv": "whois.sv",
    "sx": "whois.sx",
    "sy": "whois.tld.sy",
    "sz": "whois.sispa.org.sz",
    "tc": "whois.adamsnames.tc",
    "td": "whois.td",
    "tel": "whois.nic.tel",
    "tf": "whois.nic.tf",
    "tg": "whois.nic.tg",
    "th": "whois.thnic.co.th",
    "tj": "whois.nic.tj",
    "tk": "whois.dot.tk",
    "tl": "whois.nic.tl",
    "tm": "whois.nic.tm",
    "tn": "whois.ati.tn",
    "to": "whois.tonic.to",
    "tp": "whois.nic.tp",
    "tr": "whois.nic.tr",
    "travel": "whois.nic.travel",
    "tt": "whois.nic.tt",
    "tv": "tvwhois.verisign-grs.com",
    "tw": "whois.twnic.net.tw",
    "tz": "whois.tznic.or.tz",
    "ua": "whois.ua",
    "ug": "whois.co.ug",
    "uk": "whois.nic.uk",
    "us": "whois.nic.us",
    "uy": "whois.nic.org.uy",
    "uz": "whois.cctld.uz",
    "va": "whois.ripe.net",  # Aproximado
    "vc": "whois2.afilias-grs.net",
    "ve": "whois.nic.ve",
    "vg": "whois.adamsnames.tc",
    "vi": "whois.nic.vi",
    "vn": "whois.vnnic.vn",
    "vu": "whois.vunic.vu",
    "wf": "whois.nic.wf",
    "ws": "whois.website.ws",
    "xxx": "whois.nic.xxx",
    "ye": "whois.nic.ye",
    "yt": "whois.nic.yt",
    "za": "whois.za",
    "zm": "whois.zamnet.zm",
    "zw": "whois.zimra.co.zw",
    "ai": "whois.ai",
    "cat": "whois.cat"
}




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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Using: python find_free_short_domains.py <name>")
        print("Using: python find_free_short_domains.py test_it_in_all_tlds")
        sys.exit(1)

    name = sys.argv[1]
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"{name}_{timestamp}.txt"
    custom_fig = Figlet(font='banner3')
    print(custom_fig.renderText(cyan("JennyLab")))
    print(magenta('tld-twist v0.1'))


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
