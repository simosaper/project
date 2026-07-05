#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import socket
from platform import system
import os
import sys
import time
import re
import threading
import json
from multiprocessing.dummy import Pool
from colorama import Fore, Style, init

init(autoreset=True)

fr = Fore.RED
fh = Fore.RED
fc = Fore.CYAN
fo = Fore.MAGENTA
fw = Fore.WHITE
fy = Fore.YELLOW
fbl = Fore.BLUE
fg = Fore.GREEN
sd = Style.DIM
fb = Fore.RESET
sn = Style.NORMAL
sb = Style.BRIGHT

token = '5766471385:AAG14XYZ86AZjWNwkkivCBM6EPUqSoZGMJ0'
chatidsimo = '5555727408'
user = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0"}

COOKIE_FILE = 'ZHE.json'

def create_cookie_file():
    """Create ZHE.json file with empty template"""
    template = {
        "ZHE": "",
        "PHPSESSID": ""
    }
    with open(COOKIE_FILE, 'w') as f:
        json.dump(template, f, indent=4)
    print("\033[91m[!] ZHE.json file created successfully!\033[0m")
    print("\033[93m[!] Please edit ZHE.json and add your cookies:\033[0m")
    print("\033[96m{\033[0m")
    print('\033[96m    "ZHE": "YOUR_ZHE_COOKIE_HERE",\033[0m')
    print('\033[96m    "PHPSESSID": "YOUR_PHPSESSID_HERE"\033[0m')
    print("\033[96m}\033[0m")
    print("\033[91m[!] Script will exit. Please add cookies and run again.\033[0m")
    sys.exit(1)

def load_cookies():
    """Load cookies from ZHE.json file"""
    try:
        with open(COOKIE_FILE, 'r') as f:
            cookies = json.load(f)
            
            if not cookies.get("ZHE") or not cookies.get("PHPSESSID"):
                print("\033[91m[!] ZHE.json file is missing required cookies!\033[0m")
                print("\033[93m[!] Please add your cookies:\033[0m")
                print("\033[96m{\033[0m")
                print('\033[96m    "ZHE": "YOUR_ZHE_COOKIE_HERE",\033[0m')
                print('\033[96m    "PHPSESSID": "YOUR_PHPSESSID_HERE"\033[0m')
                print("\033[96m}\033[0m")
                print("\033[91m[!] Script will exit. Please add cookies and run again.\033[0m")
                sys.exit(1)
            
            print("\033[92m[✓] Cookies loaded from ZHE.json successfully\033[0m")
            return cookies
            
    except FileNotFoundError:
        create_cookie_file()
    except json.JSONDecodeError:
        print("\033[91m[!] Error in ZHE.json format!\033[0m")
        print("\033[93m[!] Please fix the JSON format in ZHE.json\033[0m")
        print("\033[93m[!] Example format:\033[0m")
        print("\033[96m{\033[0m")
        print('\033[96m    "ZHE": "your_zhe_cookie_here",\033[0m')
        print('\033[96m    "PHPSESSID": "your_phpsessid_here"\033[0m')
        print("\033[96m}\033[0m")
        sys.exit(1)

def check_cookies_valid():
    """Check if cookies are valid by testing Zone-h access"""
    try:
        test_url = "http://www.zone-h.org/archive/published=0/page=1"
        response = requests.get(test_url, cookies=my_cook, timeout=10)
        
        if b'<html><body>-<script type="text/javascript"' in response.content:
            print("\033[91m[!] Cookies are invalid! Please update your cookies in ZHE.json\033[0m")
            print("\033[93m[!] You need to get new cookies from Zone-h website\033[0m")
            sys.exit(1)
        elif b'captcha' in response.content:
            print("\033[91m[!] Zone-h requires captcha! Please solve captcha in browser first\033[0m")
            sys.exit(1)
        else:
            print("\033[92m[✓] Cookies are valid!\033[0m")
            return True
            
    except Exception as e:
        print("\033[91m[!] Failed to connect to Zone-h: {}\033[0m".format(str(e)))
        print("\033[93m[!] Please check your internet connection\033[0m")
        sys.exit(1)

my_cook = load_cookies()
check_cookies_valid()

url = "http://www.zone-h.org/archive/notifier="
urll = "http://zone-h.org/archive/published=0"
url2 = "http://www.defacers.org/onhold!"
url4 = "http://www.defacers.org/gold!"

def zonehh():
    print("""
        |---|    By: @simosaper11     |---|
        |---| Grabb Sites From Zone-h |---|
        \033[91m[1] \033[95mGrabb Sites By Notifier
        \033[91m[2] \033[95mGrabb Sites By Onhold
        """)
    sec = int(input("Choose Section: "))
    if sec == 1:
        notf = input("\033[95mEnter notifier: \033[92m")
        
        for i in range(1, 51):
            dz = requests.get(url + notf + "/page=" + str(i), cookies=my_cook)
            dzz = dz.content
            print(url + notf + "/page=" + str(i))
            if b'<html><body>-<script type="text/javascript"' in dzz:
                print("Change Cookies Please")
                sys.exit()
            elif b'<input type="text" name="captcha" value=""><input type="submit">' in dzz:
                print("Enter Captcha In Zone-h From Ur Browser :/")
                sys.exit()
            else:
                try:
                    dzz_str = dzz.decode('utf-8')
                except:
                    dzz_str = dzz.decode('latin-1')
                    
                Hunt_urls = re.findall(r'<td>(.*)\n\s+</td>', dzz_str)
                if '/mirror/id/' in dzz_str:
                    for xx in Hunt_urls:
                        qqq = xx.replace('...', '')
                        print('    [' + '*' + '] ' + qqq.split('/')[0])
                        with open(notf + '.txt', 'a') as rr:
                            rr.write("http://" + qqq.split('/')[0] + '\n')
                else:
                    print("Grabb Sites Completed !!")
                    sys.exit()
                    
    elif sec == 2:
        print(":* __Grabb Sites By Onhold__ ^_^")
        for qwd in range(1, 51):
            rb = requests.get(urll + "/page=" + str(qwd), cookies=my_cook)
            dzq = rb.content
            
            if b'<html><body>-<script type="text/javascript"' in dzq:
                print("Change Cookies Plz")
                sys.exit()
            elif b"captcha" in dzq:
                print("Enter captcha In Your Browser Of Site [zone-h.org]")
            else:
                try:
                    dzq_str = dzq.decode('utf-8')
                except:
                    dzq_str = dzq.decode('latin-1')
                    
                Hunt_urlss = re.findall(r'<td>(.*)\n\s+</td>', dzq_str)
                for xxx in Hunt_urlss:
                    qqqq = xxx.replace('...', '')
                    print('    [' + '*' + '] ' + qqqq.split('/')[0])
                    with open('simosaper.txt', 'a') as rrr:
                        rrr.write("http://" + qqqq.split('/')[0] + '\n')
    else:
        print("Fuck You Men")

def defacers():
    print("""
        |---| Grabb Sites From Defacers.org |--|
        \033[91m[1] \033[95mGrabb Sites By Onhold
        \033[91m[2] \033[95mGrabb Sites By Archive
        """)
    sec = int(input("Choose Section: "))
    if sec == 1:
        for i in range(1, 380):
            print("Page: " + str(i) + "\033[91m Waiting Grabbed Sites .....  <3")
            rb = requests.get(url2 + str(i), headers=user)
            okbb = rb.content
            
            try:
                okbb_str = okbb.decode('utf-8')
            except:
                okbb_str = okbb.decode('latin-1')
                
            domains = re.findall(r'title=".*" tar.?', okbb_str)
            for iii in domains:
                iii = iii.replace('" target="_blank" reel="nofollow">', "")
                iii = iii.replace('title="', "")
                iii = iii.replace('" targ', "")
                print("\033[95mhttp://" + iii + "/")
                with open("Onhold_defacer.txt", "a") as by:
                    by.writelines("http://" + iii + "/")
                    by.writelines("\n")
            print("\t\t[+] Page Saved_" + str(i) + " done [+]\n")
    elif sec == 2:
        for i in range(1, 25):
            print("Page: " + str(i) + " \033[91mWaiting Grabbed Sites Governement .....  <3")
            rb = requests.get(url4 + str(i), headers=user)
            okbb = rb.content
            
            try:
                okbb_str = okbb.decode('utf-8')
            except:
                okbb_str = okbb.decode('latin-1')
                
            domains = re.findall(r'title=".*" tar.?', okbb_str)
            for iii in domains:
                iii = iii.replace('" target="_blank" reel="nofollow">', "")
                iii = iii.replace('title="', "")
                iii = iii.replace('" targ', "")
                print("\033[95mhttp://" + iii + "/")
                with open("govSites_defacer.txt", "a") as by:
                    by.writelines("http://" + iii + "/")
                    by.writelines("\n")
            print("\t\t[+] Page Saved_" + str(i) + " done [+]\n")
    else:
        print("Fuck You Men 2")

def mirroirh():
    print("""
        |---| Grabb Sites From Mirror-h.org |--|
        \033[91m[1] \033[95mGrabb Sites By Onhold
        \033[91m[2] \033[95mGrabb Sites By Auto_Notifier
        """)
    sec = int(input("Choose Section: "))
    if sec == 1:
        url_mir = "https://mirror-h.org/archive/page/"
        try:
            for pp in range(1, 40254):
                dz = requests.get(url_mir + str(pp))
                dzz = dz.content
                
                try:
                    dzz_str = dzz.decode('utf-8')
                except:
                    dzz_str = dzz.decode('latin-1')
                    
                qwd = re.findall(r'/zone/(.*)</a></td>', dzz_str)
                print(" \033[91m[*] Please Wait To Grabb Sites ...... Page: " + str(pp))
                for ii in qwd:
                    ii = ii.replace('<i class="icon-search"></i>', "")
                    ii = ii.replace(ii[:10] if len(ii) > 10 else "", "")
                    ii = ii.replace("\r\n\r\n", "\r\n")
                    ii = ii.strip()
                    print("\033[95m" + ii)
                    with open('onzeb_mirror.txt', 'a') as rr:
                        rr.write(ii + '\n')
        except:
            pass
    elif sec == 2:
        url_mir = "https://mirror-h.org/search/hacker/"
        try:
            for ha in range(1, 2000):
                print("\033[91mWait To Grabb From Hacker: " + str(ha))
                dz = requests.get(url_mir + str(ha) + "/pages/1")
                dzz = dz.content
                
                try:
                    dzz_str = dzz.decode('utf-8')
                except:
                    dzz_str = dzz.decode('latin-1')
                    
                qwd = re.findall(r'/pages/\d" title="Last"', dzz_str)
                for i in qwd:
                    i = i.rstrip()
                    sss = i.replace("/pages/", "")
                    ss = sss.replace('" title="Last"', "")
                    ssf = int(ss) + 1
                    for ii in range(1, ssf):
                        print(" \033[91m[*] Please Wait To Grabb Sites ...... Page: " + str(ii))
                        dd = requests.get(url_mir + str(ha) + "/pages/" + str(ii))
                        op = dd.content
                        
                        try:
                            op_str = op.decode('utf-8')
                        except:
                            op_str = op.decode('latin-1')
                            
                        qwdd = re.findall(r'/zone/(.*)</a></td>', op_str)
                        for idi in qwdd:
                            idi = idi.replace('<i class="icon-search"></i>', "")
                            idi = idi.replace(idi[:10] if len(idi) > 10 else "", "")
                            idi = idi.replace("\r\n\r\n", "\r\n")
                            idi = idi.strip()
                            print("\033[95m" + idi)
                            with open('top_mirror.txt', 'a') as rr:
                                rr.write(idi + '\n')
        except:
            pass

def overflowzone():
    print("""
        |---| Grabb Sites From overflowzone.com |--|
        \033[91m[1] \033[95mGrabb Sites By Onhold
        \033[91m[2] \033[95mGrabb Sites By AutoNotifier
        """)
    sec = int(input("Choose Section: "))
    if sec == 1:
        url_ov = "http://attacker.work/onhold/onhold/page/"
        dz = requests.get(url_ov + "1")
        dzz = dz.content
        
        try:
            dzz_str = dzz.decode('utf-8')
        except:
            dzz_str = dzz.decode('latin-1')
            
        tn = re.findall(r'<a href="/onhold/page/(.*)" title="Last">', dzz_str)
        for ii in tn:
            qwd = ii.split('/')[-1]
            for ok in range(1, int(qwd)):
                okk = requests.get(url_ov + str(ok))
                print("`\t\t\t" + url_ov + str(ok))
                fel = okk.content
                
                try:
                    fel_str = fel.decode('utf-8')
                except:
                    fel_str = fel.decode('latin-1')
                    
                okkk = re.findall(r'">http://(.*)</a></td>', fel_str)
                for iii in okkk:
                    iii = iii.rstrip()
                    print("\033[95mhttp://" + iii.split('/')[0])
                    with open('onhold_attackerwork.txt', 'a') as rr:
                        rr.write("http://" + iii.split('/')[0] + '\n')
    elif sec == 2:
        url_ov = "http://attacker.work/archive/page/"
        dz = requests.get(url_ov + "1")
        dzz = dz.content
        
        try:
            dzz_str = dzz.decode('utf-8')
        except:
            dzz_str = dzz.decode('latin-1')
            
        tn = re.findall(r'<a href="/archive/page/(.*)" title="Last">', dzz_str)
        for ii in tn:
            qwd = ii.split('/')[-1]
            for ok in range(1, int(qwd)):
                okk = requests.get(url_ov + str(ok))
                print("`\t\t\t" + url_ov + str(ok))
                fel = okk.content
                
                try:
                    fel_str = fel.decode('utf-8')
                except:
                    fel_str = fel.decode('latin-1')
                    
                okkk = re.findall(r'">http://(.*)</a></td>', fel_str)
                for iii in okkk:
                    iii = iii.rstrip()
                    print("\033[95mhttp://" + iii.split('/')[0])
                    with open('archive_attackerwork.txt', 'a') as rr:
                        rr.write("http://" + iii.split('/')[0] + '\n')
    else:
        print("hhhhhhhh tnkt")

def bYPAS():
    exploit = ["/member/", "/admin/login.php", "/admin/panel.php", "/admin/", "/login.php",
               "/admin.html", "/admin.php", "/admin-login.php"]
    try:
        q = input('\033[96m Enter List Site: \033[90m ')
        q = open(q, 'r')
    except:
        print("\033[91mEnter List Sites -_- #Noob ")
        sys.exit()
    
    for lst in q:
        lst = lst.rstrip()
        print("\033[94m 	Wait Scaning ....... \033[94m" + lst)
        for exploits in exploit:
            exploits = exploits.rstrip()
            try:
                if lst[:7] == "http://":
                    lst = lst.replace("http://", "")
                if lst[:8] == "https://":
                    lst = lst.replace("https://", "")
                if lst[-1] == "/":
                    lst = lst.replace("/", "")
                
                socket.setdefaulttimeout(5)
                import http.client
                conn = http.client.HTTPConnection(lst)
                conn.request("POST", exploits)
                conn = conn.getresponse()
                htmlconn = conn.read()
                
                try:
                    htmlconn_str = htmlconn.decode('utf-8')
                except:
                    htmlconn_str = htmlconn.decode('latin-1')
                    
                if conn.status == 200 and ('type="password"' in htmlconn_str):
                    print("\033[92m [+] Admin Panel [+] ======\033[96m=======> \033[96m " + lst + exploits)
                    with open("admin_panels.txt", "a") as by:
                        by.writelines(lst + exploits + "\n")
                else:
                    print("\033[91m [-] Not Found : [-] " + lst + exploits)
            except:
                pass

def add_http():
    dz = input("Enter List Site: ")
    dz = open(dz, "r")
    for i in dz:
        i = i.rstrip()
        print("http://" + i)
        with open('aziz.txt', 'a') as rr:
            rr.write("http://" + i + '\n')
    print("Text Saved !!")

def binger():
    qwd = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0"}
    
    print("""
        \033[91m[1] \033[95mGrabb Sites By Ip List
        \033[91m[2] \033[95mGrabb Sites Fox_Contact And Bypass By Ip List
        """)
    o = int(input("Choose Section: "))
    if o == 1:
        gr = input('Give me List Ip: ')
        gr = open(gr, 'r')
        for done in gr:
            remo = []
            page = 1
            while page < 251:
                bing = "http://www.bing.com/search?q=ip%3A" + done + "+&count=50&first=" + str(page)
                opene = requests.get(bing, verify=False, headers=qwd)
                read = opene.content
                
                try:
                    read_str = read.decode('utf-8')
                except:
                    read_str = read.decode('latin-1')
                    
                findwebs = re.findall(r'<h2><a href="(.*?)"', read_str)
                for i in findwebs:
                    o_split = i.split('/')
                    if (o_split[0] + '//' + o_split[2]) in remo:
                        pass
                    else:
                        remo.append(o_split[0] + '//' + o_split[2])
                        print('[XxX] ' + (o_split[0] + '//' + o_split[2]))
                        with open('Grabbed.txt', 'a') as s:
                            s.writelines((o_split[0] + '//' + o_split[2]) + '\n')
                page = page + 5
    elif o == 2:
        qwd = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0"}
        gr = input('Give me List Ip: ')
        gr = open(gr, 'r')
        for done in gr:
            remo = []
            page = 1
            print("Wait Grabb Sites From iP: " + done)
            while page < 251:
                bing = "http://www.bing.com/search?q=ip%3A" + done + " powered by fox_contact" + "+&count=50&first=" + str(page)
                opene = requests.get(bing, verify=False, headers=qwd)
                read = opene.content
                
                try:
                    read_str = read.decode('utf-8')
                except:
                    read_str = read.decode('latin-1')
                    
                findwebs = re.findall(r'<h2><a href="(.*?)"', read_str)
                for i in findwebs:
                    o_split = i.split('/')
                    if (o_split[0] + '//' + o_split[2]) in remo:
                        pass
                    else:
                        remo.append(o_split[0] + '//' + o_split[2])
                        print('[XxX] ' + (o_split[0] + '//' + o_split[2]))
                        with open('foxcontact.txt', 'a') as s:
                            s.writelines((o_split[0] + '//' + o_split[2]) + '\n')
                page = page + 5
                
                bing = "http://www.bing.com/search?q=ip%3A" + done + " admin/login.php" + "+&count=50&first=" + str(page)
                opene = requests.get(bing, verify=False, headers=qwd)
                read = opene.content
                
                try:
                    read_str = read.decode('utf-8')
                except:
                    read_str = read.decode('latin-1')
                    
                findwebs = re.findall(r'<h2><a href="(.*?)"', read_str)
                for i in findwebs:
                    o_split = i.split('/')
                    if (o_split[0] + '//' + o_split[2]) in remo:
                        pass
                    else:
                        remo.append(o_split[0] + '//' + o_split[2])
                        try:
                            dd = requests.get(o_split[0] + '//' + o_split[2] + "/admin/login.php")
                            ddd = dd.content
                            try:
                                ddd_str = ddd.decode('utf-8')
                            except:
                                ddd_str = ddd.decode('latin-1')
                            if 'type="password"' in ddd_str:
                                print("\033[92mAdmin_Panel Site: >>>>>>\033[91m" + o_split[0] + '//' + o_split[2] + "/admin/login.php")
                                with open('admin panel.txt', 'a') as s:
                                    s.writelines((o_split[0] + '//' + o_split[2]) + '\n')
                        except:
                            pass
                page = page + 5
    else:
        print("dir numero azbi nooooooob")

def cms_detected():
    lst = input("Enter List Site: ")
    lst = open(lst, 'r')
    for i in lst:
        i = i.rstrip()
        print("\033[91m[+] \033[95mPlease Waiting To Scaning ... " + "\033[94m" + i + " \033[91m[+]")
        try:
            dz = requests.get(i)
            ok = dz.content
            
            try:
                ok_str = ok.decode('utf-8')
            except:
                ok_str = ok.decode('latin-1')
            
            if "wp-content" in ok_str:
                print("\033[92mWp Site : >>>>>>>>>>>>>>\033[91m" + i + "/wp-login.php")
                with open("wp sites.txt", "a") as wpp:
                    wpp.writelines(i + "/wp-login.php" + "\n")
            elif "com_content" in ok_str:
                print("\033[92mJm Site: >>>>>>>>>>>>>>\033[91m" + i + "/administrator/")
                with open("joomla sites.txt", "a") as jmm:
                    jmm.writelines(i + "/administrator/" + "\n")
            elif "index.php?route" in ok_str:
                print("\033[92mOpenCart Site: >>>>>>>>>>>>>>\033[91m" + i + "/admin/")
                with open("OpenCart sites.txt", "a") as opncrt:
                    opncrt.writelines(i + "/admin/" + "\n")
            elif "/node/" in ok_str:
                print("\033[92mDrupal Site: >>>>>>>>>>>>>>\033[91m" + i + "/user/login")
                with open("Drupal sites.txt", "a") as drbl:
                    drbl.writelines(i + "/user/login" + "\n")
            else:
                bypass = ["/admin/login.php", "/admin/", "/login.php", "/admin.html", "/admin.php", "/member/"]
                found_admin = False
                for byp in bypass:
                    byp = byp.rstrip()
                    try:
                        dd = requests.get(i + byp)
                        ddd = dd.content
                        try:
                            ddd_str = ddd.decode('utf-8')
                        except:
                            ddd_str = ddd.decode('latin-1')
                        if 'type="password"' in ddd_str:
                            print("\033[92mAdmin_Panel Site: >>>>>>\033[91m" + i + byp)
                            with open("Admin Sites.txt", "a") as by:
                                by.writelines(i + byp + "\n")
                            found_admin = True
                    except:
                        pass
                
                if not found_admin:
                    print("\033[91m[-] Not Found Cms: [-] " + "\033[91m" + i)
        except:
            pass

def spotii():
    url_spot = "http://www.spotify.com/us/xhr/json/isEmailAvailable.php?signup_form[email]="
    
    try:
        ok = input("{}root@simosaper11~# Enter List Email: ".format(fy))
        okd = open(ok, 'r')
    except:
        print("{}zebi enter list email -_- nooob".format(fh))
        return
    
    for i in okd:
        i = i.rstrip()
        qwd = url_spot + i + "&email=" + i
        try:
            dz = requests.get(qwd, headers=user)
            dzz = dz.content
            
            try:
                dzz_str = dzz.decode('utf-8')
            except:
                dzz_str = dzz.decode('latin-1')
                
            if 'false' in dzz_str:
                print("{}   [LIVE]     {}".format(fg, i))
                with open("spotify checked.txt", "a") as zebi:
                    zebi.writelines(i + '\n')
            else:
                print("{}   [DEAD]     {}".format(fh, i))
        except:
            print("{}   [ERROR]    {}".format(fh, i))

def clearscrn():
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(4. / 100)

def helper4():
    clearscrn()
    banner = """\033[94m
 _______ _________ _______  _______  _______  _______  _______  _______  _______ 
(  ____ \\__   __/(       )(  ___  )(  ____ \(  ___  )(  ____ )(  ____ \(  ____ )
| (    \/   ) (   | () () || (   ) || (    \/| (   ) || (    )|| (    \/| (    )|
| (_____    | |   | || || || |   | || (_____ | (___) || (____)|| (__    | (____)|
(_____  )   | |   | |(_)| || |   | |(_____  )|  ___  ||  _____)|  __)   |     __)
      ) |   | |   | |   | || |   | |      ) || (   ) || (      | (      | (\ (   
/\____) |___) (___| )   ( || (___) |/\____) || )   ( || )      | (____/\| ) \ \__
\_______)\_______/|/     \|(_______)\_______)|/     \||/       (_______/|/   \__/
                                                                                
                                                                                |___/                             
          """
    print("""\033[95m
 _______ _________ _______  _______  _______  _______  _______  _______  _______ 
(  ____ \\__   __/(       )(  ___  )(  ____ \(  ___  )(  ____ )(  ____ \(  ____ )
| (    \/   ) (   | () () || (   ) || (    \/| (   ) || (    )|| (    \/| (    )|
| (_____    | |   | || || || |   | || (_____ | (___) || (____)|| (__    | (____)|
(_____  )   | |   | |(_)| || |   | |(_____  )|  ___  ||  _____)|  __)   |     __)
      ) |   | |   | |   | || |   | |      ) || (   ) || (      | (      | (\ (   
/\____) |___) (___| )   ( || (___) |/\____) || )   ( || )      | (____/\| ) \ \__
\_______)\_______/|/     \|(_______)\_______)|/     \||/       (_______/|/   \__/
                                                                                 
                                  
                                  Script Name : simo scraper ^_^
                                
                                     """)
    slowprint("\n\t\t\t\t\tPowered By : mohamed saper " + "\n\t\t\t\t\t\t            tg : t.me/simosaper11")
    print("")
    try:
        qq = 1
        if qq == 1:
            clearscrn()
            print(banner)
            zonehh()
        elif qq == 2:
            clearscrn()
            print(banner)
            defacers()
        elif qq == 3:
            clearscrn()
            print(banner)
            mirroirh()
        elif qq == 4:
            clearscrn()
            print(banner)
            overflowzone()
        elif qq == 5:
            clearscrn()
            print(banner)
            bYPAS()
        elif qq == 6:
            clearscrn()
            print(banner)
            add_http()
        elif qq == 7:
            clearscrn()
            print(banner)
            binger()
        elif qq == 8:
            clearscrn()
            print(banner)
            cms_detected()
        elif qq == 9:
            clearscrn()
            print(banner)
            spotii()
        else:
            print("Invalid choice!")
    except:
        pass

if __name__ == "__main__":
    helper4()
