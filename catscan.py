import argparse
from argparse import RawDescriptionHelpFormatter
from datetime import datetime
import hashlib
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
from os import getcwd, path
import re

import jinja2
from lxml import html, etree
import requests
try:
    import ssdeep
except ImportError:
    ssdeep = None
import urllib3
import xmltodict

results = {}
cwd = getcwd()
datatables_css = f'<link rel="stylesheet" type="text/css" href="{cwd}/css/jquery.dataTables.min.css">'
jquery = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/jquery-3.5.1.min.js"></script>'
datatables = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/jquery.dataTables.min.js"></script>'
datatables_celledit = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/dataTables.cellEdit.js"></script>'
ssdeep_js = f'<script type="text/javascript" charset="utf8" src="{cwd}/js/ssdeep.js"></script>'

jinja_env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "template.html"
template = templateEnv.get_template(TEMPLATE_FILE)


def parse_nmap_xml(nmap_file, ports):
    hosts = []
    nmap_scan = xmltodict.parse(nmap_file.read())
    for host in nmap_scan['nmaprun']['host']:
        ipv4_addr = host['address']['@addr']
        if isinstance(host['ports']['port'], list):
            for port in host['ports']['port']:
                if int(port['@portid']) in ports:
                    hosts.append(f"{ipv4_addr}:{port['@portid']}")
        else:
            if int(host['ports']['port']['@portid']) in ports:
                hosts.append(f"{ipv4_addr}:{host['ports']['port']['@portid']}")
    scan_set = {'http://' + host if host[-3:] == '80' else 'http://' + host for host in hosts}
    return scan_set


def build_list(list_file, ports):
    regex = re.compile(r"^(http?:\/\/)?.+?(:[0-9]{0,5})?$")
    scan_set = set()
    lines = [line.rstrip() for line in list_file.readlines()]
    for line in lines:
        line = re.match(regex, line)
        if not line:
            pass
        elif line[1] and line[2]: 
            scan_set.add(line[0])
        elif line[1] and not line[2]: 
            print('Protocol no port')
            if line[1] == 'http://':
                scan_set.add(line[0])
            else:
                for port in ports:
                
                    if str(port) == '80':
                        uri = line[0].replace('http://', 'http://') + ':' + str(port)
                        scan_set.add(uri)
                    else:
                        uri = line[0] + ':' + str(port)
                        scan_set.add(uri)
            print(scan_set)
            exit()

        elif not line[1] and line[2]: 
            if line[2] == ':80':
                uri = 'http://' + line[0]
            else:
                uri = 'http://' + line[0]
            scan_set.add(uri)
        elif not line[1] and not line[2]:  
            for port in ports:
                if str(port) == '80':
                    uri = 'http://' + line[0] + ':' + str(port)
                else:
                    uri = 'http://' + line[0] + ':' + str(port)
                scan_set.add(uri)
    return scan_set


def prompt(question, default=None):

    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        choice = " [y/n] "
    elif default == "yes":
        choice = " [Y/n] "
    elif default == "no":
        choice = " [y/N] "
    else:
        raise ValueError(f'Invalid default answer: {default}')

    while True:
        print(question + choice)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print('[*] Please respond with "[y]es" or "[n]o".')


def scan(timeout, validate_certs, no_redirect, user_agent, fuzzy, verbose, uri):
    headers = {'User-Agent': user_agent}
    regex = re.compile(r"type=[\"|\']password[\"|\']", re.IGNORECASE)
    parser = etree.HTMLParser()
    title, login, redirect, md5_hash, fuzzy_hash = None, None, None, None, None
    error = None
    results[uri] = [title, login, redirect, md5_hash, fuzzy_hash]
    try:
        resp = requests.get(uri, headers=headers, timeout=timeout, verify=validate_certs,
                            allow_redirects=no_redirect)
        if resp.content:
            md5_hash = hashlib.md5(resp.content).hexdigest()
            tree = html.fromstring(resp.content, parser=parser)
            try:
                title = tree.find('.//title').text.lstrip().rstrip()
                if ',' in title:
                    title = '"' + title + '"'  
            except AttributeError:
                if verbose:
                    print(f'[-] {uri} - attribute error; page may lack title element')
            login = re.search(regex, resp.content.decode('ISO-8859-1'))
            if login:
                login = True
            if fuzzy:
                fuzzy_hash = ssdeep.hash(resp.content)
            elif no_redirect is True:
                if resp.url.strip('/') != uri:
                    redirect = resp.url
        results[uri] = [title, resp.status_code, login, redirect, md5_hash, fuzzy_hash]
    except requests.exceptions.ConnectTimeout:
        error = 'Timeout.'
        results[uri].insert(1, error)
    except requests.exceptions.ReadTimeout:
        error = 'Timeout.'
        results[uri].insert(1, error)
    except requests.exceptions.SSLError:
        error = 'Timeout'
        results[uri].insert(1, error)
    except requests.exceptions.TooManyRedirects:
        error = 'Timeout'
        results[uri].insert(1, 'Too many redirects')

    except requests.exceptions.ConnectionError as err:
        err_msg = str(err.args[0])
        if 'BadStatusLine' in err_msg:
            error = 'Timeout'
            results[uri].insert(1, 'Timeout')
        elif 'Connection refused' in err_msg:
            error = 'Timeout'
            results[uri].insert(1, error)
        elif 'Connection reset by peer' in err_msg:
            error = 'Timeout'
            results[uri].insert(1, error)
        else:  
            error = err_msg
            results[uri].insert(1, 'Timeout')
    if verbose and error:
        print(f'[-] Error scanning {uri}: {error}')
    print(f'[-] now scan {uri}:')


def main():
    user_agent = '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36'''

    parser = argparse.ArgumentParser(description='Scan and categorize web servers using a searchable and sortable'
                                                 'HTML report.',
                                     epilog='list input: python3 catscan.py -l <ips.txt> -p 80 80 8080 -t 10\n'
                                            'Nmap xml:   python3 catscan.py -x <nmap.xml>',
                                     formatter_class=RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-x', '--xml', dest='nmap_xml', type=argparse.FileType('r'),
                       help='Use an Nmap XML file as input.')
    group.add_argument('-l', '--list', dest='host_list', type=argparse.FileType('r'),
                       help='Text file containing list of IPs or hostnames separated by line.')
    parser.add_argument('-p', '--ports', dest='ports', nargs='+', required=False, default=[80, 80],
                        help='List of ports to scan. Default 80 and 80.')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=10,
                        help='Number of threads. Default 10.')
    parser.add_argument('-T', '--timeout', dest='timeout', type=int, default=5,
                        help='Timeout in seconds. Default 5.')
    parser.add_argument('-o', '--output', dest='output', required=False,
                        help='Name of HTML report. Default based on date/time.')
    parser.add_argument('-u', '--user-agent', dest='user_agent', required=False, default=user_agent,
                        help='User-Agent string.')
    parser.add_argument('-r', '--no-redirect', dest='no_redirect', required=False, default=True, action='store_false',
                        help='Do not follow redirects. Catscan follows redirects by default.')
    parser.add_argument('-k', '--validate', dest='validate_certs', required=False, default=False,
                        action='store_true', help='Validate certificates. Default false.')
    parser.add_argument('-n', '--notes', dest='notes', required=False, default=False,
                        action='store_true', help='Add a writable "Notes" column to HTML report.')
    parser.add_argument('-f', '--fuzzy', dest='fuzzy', required=False, default=False,
                        action='store_true', help='Use "fuzzy" hashes to identify similar sites.')
    parser.add_argument('-v', '--verbose', dest='verbose', required=False, default=False,
                        action='store_true')
    args = parser.parse_args()

    nmap_file = args.nmap_xml
    list_file = args.host_list
    ports = args.ports
    timeout = args.timeout
    threads = args.threads
    output = args.output
    user_agent = args.user_agent
    no_redirect = args.no_redirect
    validate_certs = args.validate_certs
    notes = args.notes
    fuzzy = args.fuzzy
    verbose = args.verbose
    start_time = datetime.now()
    if fuzzy and not ssdeep:
        fuzzy = False
        print('[-] Error importing ssdeep module. Fuzzy hashing functionality not available.')
    if not output:
        output = f'catscan_report_{start_time.strftime("%a_%d%b%Y_%H%M").lower()}.html'
    if output:
        if path.isfile(output):
            ans = prompt(f'[*] Output file {output} already exists. Overwrite?', None)
            if not ans:
                print('[-] Provide new name or overwrite existing report. Exiting.')
                exit()
    if nmap_file:
        scan_list = parse_nmap_xml(nmap_file, ports)
    elif list_file:
        scan_list = build_list(list_file, ports)
    func = partial(scan, timeout, validate_certs, no_redirect, user_agent, fuzzy, verbose)
    pool = ThreadPool(threads)
    pool.map(func, scan_list)
    pool.close()
    pool.join()
    end_scan_time = datetime.now()
    if verbose:
        print(f'[*] Scan time: {(end_scan_time - start_time).total_seconds()} seconds')
    print(f'[*] {len(scan_list)} hosts scanned')
    end_run_time = datetime.now()
    print(f'[*] Total run time: {(end_run_time - start_time).total_seconds()} seconds')

    title_counts, content_counts = {}, {}
    for value in results.values():
        if value[0] in title_counts:
            title_counts[value[0]] += 1
        else:
            title_counts[value[0]] = 1
        if value[4] in content_counts:
            content_counts[value[4]][0] += 1
        else:
            content_counts[value[4]] = [1, value[0]]

    with open(output, 'w', encoding="utf8") as html_report:
        html_report.write(template.render(
            start_time=start_time.strftime("%a_%d%b%Y_%H%M").lower(),
            datatables_css=datatables_css,
            jquery=jquery,
            datatables=datatables,
            datatables_celledit=datatables_celledit,
            ssdeep_js=ssdeep_js,
            redirect_column=no_redirect,
            notes_column=notes,
            fuzzy=fuzzy,
            results=results,
            title_counts=title_counts,
            content_counts=content_counts
        ))

    print(f'[*] Report written to {output}')


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
