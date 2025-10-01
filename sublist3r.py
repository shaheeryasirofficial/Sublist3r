#!/usr/bin/env python3
# coding: utf-8
# Sublist3r v3.0 - Enhanced Edition
# Original by Ahmed Aboul-Ela - twitter.com/aboul3la
# Enhanced by Shaheer Yasir

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter
from urllib.parse import urlparse, unquote  # Fixed for Python 3

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Disable SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Console Colors (using colorama for cross-platform)
try:
    import colorama
    colorama.init(autoreset=True)
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
except ImportError:
    print("[!] Install colorama for colored output: pip install colorama")
    G = Y = B = R = W = ''

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''

def banner():
    print(f"""%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \\___ \\| | | | '_ \\| | / __| __| |_ \\| '__|
                 ___) | |_| | |_) | | \\__ \\ |_ ___) | |
                |____/ \\__,_|_.__/|_|_|___/\\__|____/|_|%s%s

                # Sublist3r v3.0 - Enhanced by Shaheer Yasir (2025)
    """ % (R, W, Y))

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-j', '--json', help='Save the results to json file', default=False, action='store_true')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()

def write_file(filename, subdomains, json_output=False):
    print(f"{Y}[-] Saving results to file: {W}{R}{filename}{W}")
    if json_output:
        with open(filename, 'w') as f:
            json.dump(list(subdomains), f, indent=4)
    else:
        with open(filename, 'w') as f:
            for subdomain in subdomains:
                f.write(subdomain + os.linesep)

def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

class EnumeratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        self.print_(G + f"[-] Searching now in {self.engine_name}.." + W)
        return

    def send_req(self, query, page_no=1):
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return ""
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def extract_domains(self, resp):
        return

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        return

    def generate_query(self):
        return

    def get_page(self, num):
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)

            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):
                return self.subdomains

            resp = self.send_req(query, page_no)

            if not self.check_response_errors(resp):
                return self.subdomains

            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains

class EnumeratorBaseThreaded(multiprocessing.Process, EnumeratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        EnumeratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)

# GoogleEnum (updated)
class GoogleEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://www.google.com/search?q={query}&start={page_no}"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        try:
            # Updated regex for modern Google
            cite_regx = re.compile(r'<div class="g".*?>(.*?)</div>', re.S)
            g_blocks = cite_regx.findall(resp)
            for block in g_blocks:
                cite = re.search(r'<cite.*?>(.*?)</cite>', block, re.S)
                if cite:
                    link = cite.group(1).strip()
                    if link.startswith('/url?q='):
                        link = link[7:].split('&')[0]
                    if not link.startswith('http'):
                        link = "http://" + link
                    subdomain = urlparse(link).netloc
                    if subdomain and subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain)
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if 'Our systems have detected unusual traffic' in resp:
            self.print_(R + "[!] Error: Google blocking requests" + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(2)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = f"site:{self.domain} -www.{self.domain}"
        return query

# YahooEnum (from original, updated)
class YahooEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        link_regx2 = re.compile(r'<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile(r'<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?b>", "", link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query

# AskEnum (from original)
class AskEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        super(AskEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

# BingEnum (from original)
class BingEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        super(BingEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = []
        link_regx = re.compile(r'<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile(r'<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r'<(\/)?strong>|<span.*?>|<|>', '', link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query

# BaiduEnum (from original)
class BaiduEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        super(BaiduEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.querydomain = self.domain

    def extract_domains(self, resp):
        links = []
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile(r'<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub(r'<.*?>|>|<|&nbsp;', '', link)  # Fixed raw string
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, None)
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query

# NetcraftEnum (from original, fixed urllib.unquote)
class NetcraftEnum(EnumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers
