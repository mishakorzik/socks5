from datetime import datetime, date
import os, sys, time, json, socket, threading, select, argparse, platform, requests, random, socks
from pick import pick
import urllib3
import subprocess as sp
from urllib3.contrib.socks import SOCKSProxyManager

global NGROK_TOKEN
NGROK_TOKEN = "" # put your ngrok token

parser = argparse.ArgumentParser()
parser.add_argument('--token', help="Change ngrok token for exprore proxy", default="system", type=str)
parser.add_argument('--username', help="Username for socks authentication⠀- (default: he1zen)", default="he1zen", type=str)
parser.add_argument('--password', help="Password for socks authentication⠀- (default: he1zen)", default="he1zen", type=str)
parser.add_argument('--console', help="Start console for control proxy - (on/off) (default: off)", default="off", type=str)
parser.add_argument('--exprore', help="Exprore proxy server to internet⠀- (on/off) (default: off)", default="off", type=str)
parser.add_argument('--auth', help="Enable or disable proxy basic auth - (on/off) (default: off)", default="off", type=str)
parser.add_argument('--adblock', help="Block adverstiment on websites⠀- (on/off) (default: off)", default="off", type=str)
parser.add_argument('--advanced', help="Show advanced proxy infomation⠀- (on/off) (default: off)", default="off", type=str)
parser.add_argument('--trackblock', help="Block trackers IP on websites⠀- (on/off) (default: off)", default="off", type=str)
parser.add_argument('--malwareblock', help="Block all malware on websites⠀- (on/off) (default: off)", default="off", type=str)
parser.add_argument('--chinablock', help="Block all chinese IP on websites - (on/off) (default: off)", default="off", type=str)
parser.add_argument('--multihop', help="Make a double encrypted connection - (on/off) (default: off)", default="off", type=str)
parser.add_argument('--blacklist', help="Block all IP addresses in the list⠀- (list/off) (default: off)", default="off", type=str)
parser.add_argument('--whitelist', help="Allow to connecting IP in the list⠀- (list/off) (default: off)", default="off", type=str)
parser.add_argument('--version', help="Change the current version of socks⠀- (5/4) (default: 5)", default=5, type=int)
parser.add_argument('--port', help="port to run the server on the local - (default: 1080)", default=1080, type=int)
parser.add_argument('--max', help="Maximum allowed connections to socks⠀- (default: 256)", default=128, type=int)
args = parser.parse_args()

################
PORT = args.port
if PORT == 0:
    PORT = random.randrange(1024, 9999)
elif PORT == 00:
    PORT = random.randrange(10000, 60000)
TOKEN = args.token
LISTEN = args.max
AUTH = args.auth
IPINFO = args.advanced
ADBLOCK = args.adblock
EXPRORE = args.exprore
SOCKS = args.version
MULTIHOP = args.multihop
MALWAREBLOCK = args.malwareblock
CHNBLOCK = args.chinablock
DONOTRACK = args.trackblock
BLACKLIST = args.blacklist
WHITELIST = args.whitelist
CONSOLE = args.console
REFUSED = b"\x05"

now = datetime.now()
current_today = date.today().strftime("%d.%m.%Y")
log = open("log.txt", "w")
log.write(f"---socks5 logging {current_today}---\n")

global ngrokregion
global console_status
global connections
global kbytesdata
global proxy_ips
global ipchanger
global showtext
proxy_ips = []
showtext = False
ngrokregion = "eu"
connections = 0
kbytesdata = 0
ipchanger = "null"
console_status = False
ngroklink = "https://github.com/mishakorzik/mishakorzik.menu.io/blob/master/ngrok?raw=true"
iptokens = ["6bd5ffce9c4696", "1f52b223ee2526", "3009b86d17c3cc"]

################

if 513 <= LISTEN:
    now = datetime.now()
    current_time = now.strftime(" %H:%M:%S")
    current_today = date.today().strftime("%d.%m.%Y /")
    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Failed to start proxy server, limit of maximum connections \x1B[37m")
    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Allowed maximum number of connections 512\x1B[37m")
    exit(3)
    exit(3)

################

if SOCKS == 5:
    VERSION = 5
elif SOCKS == 4:
    VERSION = 4
else:
    now = datetime.now()
    current_time = now.strftime(" %H:%M:%S")
    current_today = date.today().strftime("%d.%m.%Y /")
    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Unknown version of socks entered, stopping\x1B[37m")
    exit(3)
    exit(3)

def cls():
    if sys.platform == 'win32':
        # clear in windows, java
        os.system('cls')
    else:
        # clear in linux, android, ubuntu
        os.system('clear')

def set_multihop():
    time.sleep(3)
    global ipchanger
    global proxy_ips
    while True:
        try:
            for rand in proxy_ips:
                ipchanger = "multihop|"+str(rand)
                time.sleep(1.5)
        except IndexError:
            pass

def pproxy_multihop():
    global ipchanger
    global showtext
    global usernamee
    global passwordd
    global totalproxies
    global proxy_ips
    usernamee = ""
    passwordd = ""
    try:
        readloc = requests.get("http://ipwho.is").json()
        country = readloc["country_code"]
        continent = readloc["continent_code"]
    except:
        readloc = requests.get("https://ipapi.co//json/").json()
        country = readloc["country_code"]
        continent = readloc["continent_code"]
    try:
        get = []
        getdat = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000").text
        getdat = getdat.split()
        for dat in getdat:
            get.append(dat)
    except:
        get = []
        apis = ["gbk5g418kazqnb21v13c4sp6swhvig0ism1p9kvc", "nufdzszedo42gw56p01f9vih9s0a6c1gshvkyx6y", "dzo01ucv13sb8mrp9zsfq156s67dzjf8cpig15d3", "25zanszic317d9a78ksx3e682od9i5459pk14c21", "2ju96k54817qqo9dgsqnp1ktod7o0zunllbqntpe", "hrotrozm4spomxtt96vjnlif5lxo18t1nh9axylm", "c419inwxbfywyev6ifbth98zsayerycnyzvu3lb4"]
        api = random.choice(apis)
        getdat = requests.get("https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=10", headers={"Authorization": api}).json()
        getdat = getdat["results"]
        for dat in getdat:
            username = dat["username"]
            password = dat["password"]
            ip = dat["proxy_address"]
            port = str(dat["port"])
            get.append(f"{username}:{password}@{ip}:{port}")
    totalproxies = 0
    proxy_ips = []
    for rand in get:
        try:
            if "@" in rand:
                serv = rand
                check = requests.get("https://www.google.com/", timeout=4, headers={"User-Agent": "Mozilla/5.0"}, proxies={"https": "socks5://"+serv})
                proxy_ips.append(serv)
            else:
                check = requests.get("https://www.google.com", timeout=4, proxies={"https": "socks5://"+rand}).text
                totalproxies = totalproxies + 1
                proxy_ips.append(rand)
        except:
            pass
    if showtext == True:
        try:
            ip, _ = rand.split(":")
        except:
            auth, proxy = rand.split("@")
            ip, _ = proxy.split(":")
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        total = str(totalproxies)
        print(f"\r\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] Successfully found multihop proxies {total}\x1B[37m")
        showtext = False
    ipchanger = "multihop|"+rand

def proxyy(server):
    global ipchanger
    if server == "off" or server == "Off":
        ipchanger = "null"
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] Proxy have been successfully disabled\x1B[37m")
    else:
        try:
            ip, port = server.split(":")
            ipchanger = ip+":"+str(port)
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] Proxy successfully changed to: {ipchanger}\x1B[37m")
        except:
            get = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=35").text
            if get == "":
                get = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=65").text
                if get == "":
                    get = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=95").text
                    if get == "":
                        get = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=125").text
            stop = False
            get = get.split()
            rand = random.choice(get)
            ip, port = rand.split(":")
            ip = str(ip)
            port = str(port)
            try:
                rand = random.choice(get)
                ip, port = rand.split(":")
                ip = str(ip)
                port = str(port)
                check = requests.get("https://google.com/", timeout=3, proxies={"https": "socks5://"+ip+":"+port})
            except:
                try:
                    rand = random.choice(get)
                    ip, port = rand.split(":")
                    ip = str(ip)
                    port = str(port)
                    check = requests.get("https://google.com/", timeout=3, proxies={"https": "socks5://"+ip+":"+port})
                except:
                    try:
                        rand = random.choice(get)
                        ip, port = rand.split(":")
                        ip = str(ip)
                        port = str(port)
                        check = requests.get("https://google.com/", timeout=3, proxies={"https": "socks5://"+ip+":"+port})
                    except:
                        try:
                            rand = random.choice(get)
                            ip, port = rand.split(":")
                            ip = str(ip)
                            port = str(port)
                            check = requests.get("https://google.com/", timeout=3, proxies={"https": "socks5://"+ip+":"+port})
                        except:
                            try:
                                rand = random.choice(get)
                                ip, port = rand.split(":")
                                ip = str(ip)
                                port = str(port)
                                check = requests.get("https://google.com/", timeout=3, proxies={"https": "socks5://"+ip+":"+port})
                            except:
                                stop = True
            if stop == False:
                try:
                    ipchanger = rand
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] Proxy successfully changed to: {rand}\x1B[37m")
                except:
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Failed to change proxy, try again\x1B[37m")
            else:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] proxy server could not be found, try again later\x1B[37m")

def ngrok():
    global exprore1
    global exprore2
    global token
    global ngrokregion
    global NGROK_TOKEN
    ngrokfilecheck = os.path.isfile("ngrok")
    if ngrokfilecheck == False:
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        arch = platform.uname()[4]
        if arch == "aarch64":
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] Downloading ngrok v3.0.6 (optimal)\x1B[37m")
            os.system("wget -q "+ngroklink)
            os.system("mv ngrok?raw=true ngrok")
            os.system("chmod +x ngrok")
        else:
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] Downloading ngrok v3.1.0 (optimal)\x1B[37m")
            os.system("wget -q https://github.com/mishakorzik/mishakorzik.menu.io/raw/master/ngrok-v3-stable-linux-amd64.tgz")
            os.system("tar -xvf ngrok-v3-stable-linux-amd64.tgz")
            os.system("rm -rf ngrok-v3-stable-linux-amd64.tgz")
            os.system("chmod +x ngrok")
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] Ngrok successfully installed\x1B[37m")
        time.sleep(1)
    exprore1 = "null"
    exprore2 = "null"
    token = NGROK_TOKEN
    p = str(PORT)
    os.system("./ngrok authtoken "+token)
    help = f"Please select a ngrok region for start ngrok server.\nUse the ↑ and ↓ keys to select which entry is highlighted."
    options = [
"North America (US) (Columbus)", 
"South America (BR) (São Paulo)", 
"West Europe (DE) (Frankfurt)", 
"Asia Pacific (SG) (Singnapore)", 
"South Asia (IN) (Mumbai)", 
"East Asia (JP) (Tokyo)", 
"Oceania (AU) (Sydney)"]
    option, index = pick(options, help,  indicator='*', default_index=1)
    if option == "West Europe (DE) (Frankfurt)":
        os.system(f"./ngrok tcp {p} --region=eu > /dev/null 2>&1 &")
        ngrokregion = "eu"
    elif option == "North America (US) (Columbus)":
        os.system(f"./ngrok tcp {p} --region=us > /dev/null 2>&1 &")
        ngrokregion = "us"
    elif option == "South America (BR) (São Paulo)":
        os.system(f"./ngrok tcp {p} --region=sa > /dev/null 2>&1 &")
        ngrokregion = "sa"
    elif option == "East Asia (JP) (Tokyo)":
        os.system(f"./ngrok tcp {p} --region=jp > /dev/null 2>&1 &")
        ngrokregion = "jp"
    elif option == "South Asia (IN) (Mumbai)":
        os.system(f"./ngrok tcp {p} --region=in > /dev/null 2>&1 &")
        ngrokregion = "in"
    elif option == "Asia Pacific (SG) (Singnapore)":
        os.system(f"./ngrok tcp {p} --region=ap > /dev/null 2>&1 &")
        ngrokregion = "ap"
    elif option == "Oceania (AU) (Sydney)":
        os.system(f"./ngrok tcp {p} --region=au > /dev/null 2>&1 &")
        ngrokregion = "au"
    else:
        os.system(f"./ngrok tcp {p} --region=us > /dev/null 2>&1 &")
        ngrokregion = "us"
    now = datetime.now()
    current_time = now.strftime(" %H:%M:%S")
    current_today = date.today().strftime("%d.%m.%Y /")
    print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] Starting the server and main components\x1B[37m")
    time.sleep(3)
    try:
        get = requests.get("http://127.0.0.1:4040/api/tunnels/command_line").json()
    except:
        try:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
            time.sleep(5)
            get = requests.get("http://127.0.0.1:4040/api/tunnels/command_line").json()
        except:
            try:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                time.sleep(5)
                get = requests.get("http://127.0.0.1:4040/api/tunnels/command_line").json()
            except:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] ngrok error, please restart server!\x1B[37m")
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] if that doesn't work then try entering your ngrok token\x1B[37m")
                exit(1)
    config = get["config"]
    addr = config["addr"]
    if addr == "localhost:"+str(PORT):
        exprore1 = get["public_url"]
        exprore1 = exprore1.replace("tcp://", "")
        ip, port=exprore1.split(":")
        exprore1 = socket.gethostbyname(str(ip))
        exprore1 = exprore1+":"+str(port)
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] You ngrok status page: http://127.0.0.1:4040\x1B[37m")
    else:
        try:
            get = requests.get("http://127.0.0.1:4041/api/tunnels/command_line").json()
        except:
            try:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                time.sleep(5)
                get = requests.get("http://127.0.0.1:4041/api/tunnels/command_line").json()
            except:
                try:
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                    time.sleep(5)
                    get = requests.get("http://127.0.0.1:4041/api/tunnels/command_line").json()
                except:
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] ngrok error, please restart server!\x1B[37m")
                    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] if that doesn't help then try entering your ngrok token\x1B[37m")
                    exit(1)
        config = get["config"]
        addr = config["addr"]
        if addr == "localhost:"+str(PORT):
            exprore1 = get["public_url"]
            exprore1 = exprore1.replace("tcp://", "")
            ip, port=exprore1.split(":")
            exprore1 = socket.gethostbyname(str(ip))
            exprore1 = exprore1+":"+str(port)
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] You ngrok status page: http://127.0.0.1:4041\x1B[37m")
        else:
            try:
                get = requests.get("http://127.0.0.1:4042/api/tunnels/command_line").json()
            except:
                try:
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                    time.sleep(5)
                    get = requests.get("http://127.0.0.1:4042/api/tunnels/command_line").json()
                except:
                    try:
                        now = datetime.now()
                        current_time = now.strftime(" %H:%M:%S")
                        current_today = date.today().strftime("%d.%m.%Y /")
                        print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                        time.sleep(5)
                        get = requests.get("http://127.0.0.1:4042/api/tunnels/command_line").json()
                    except:
                        now = datetime.now()
                        current_time = now.strftime(" %H:%M:%S")
                        current_today = date.today().strftime("%d.%m.%Y /")
                        print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] ngrok error, please restart server!\x1B[37m")
                        print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] if that doesn't work then try entering your ngrok token\x1B[37m")
                        exit(1)
            config = get["config"]
            addr = config["addr"]
            if addr == "localhost:"+str(PORT):
                exprore1 = get["public_url"]
                exprore1 = exprore1.replace("tcp://", "")
                ip, port=exprore1.split(":")
                exprore1 = socket.gethostbyname(str(ip))
                exprore1 = exprore1+":"+str(port)
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] You ngrok status page: http://127.0.0.1:4042\x1B[37m")
            else:
                try:
                    get = requests.get("http://127.0.0.1:4042/api/tunnels/command_line").json()
                except:
                    try:
                        now = datetime.now()
                        current_time = now.strftime(" %H:%M:%S")
                        current_today = date.today().strftime("%d.%m.%Y /")
                        print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                        time.sleep(5)
                        get = requests.get("http://127.0.0.1:404e/api/tunnels/command_line").json()
                    except:
                        try:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] ngrok error, reconnecting to server\x1B[37m")
                            time.sleep(5)
                            get = requests.get("http://127.0.0.1:4043/api/tunnels/command_line").json()
                        except:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] ngrok error, please restart server!\x1B[37m")
                            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] if that doesn't work then try entering your ngrok token\x1B[37m")
                            exit(1)
                config = get["config"]
                addr = config["addr"]
                if addr == "localhost:"+str(PORT):
                    exprore1 = get["public_url"]
                    exprore1 = exprore1.replace("tcp://", "")
                    ip, port=exprore1.split(":")
                    exprore1 = socket.gethostbyname(str(ip))
                    exprore1 = exprore1+":"+str(port)
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] You ngrok status page: http://127.0.0.1:4043\x1B[37m")
                else:
                    exprore1 = "null"
                    exprore2 = "null"
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Failed to exprore proxy, try again later\x1B[37m")
                    os.system(f"""pkill -f 'ngrok tcp {PORT} --region={ngrokregion}'""")
                    exit(53)
                    exit(53)

try:
    exprore1 = "null"
    exprore2 = "null"
    if EXPRORE == "on" or EXPRORE == "On" or EXPRORE == "ON" or EXPRORE == "online" or EXPRORE == "Online" or EXPRORE == "start" or EXPRORE == "True" or EXPRORE == "true" or EXPRORE == "Start":
        ngrok()
        if TOKEN == "system" or TOKEN == "sys":
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] if you don't have an ngrok token, the token will be provided by the system\x1B[37m")
            print(f"\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] if fail to open ports through ngrok, then use your token with the --token command\x1B[37m")
        else:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] the existing ngrok token is used\x1B[37m")
            print(f"\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] which was entered with the --token parameter\x1B[37m")
except:
     now = datetime.now()
     current_time = now.strftime(" %H:%M:%S")
     current_today = date.today().strftime("%d.%m.%Y /")
     print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] ngrok error, failed to start ngrok error code: 0x51\x1B[37m")
     exit(52)
     exit(52)

def multihop_check():
    time.sleep(7)
    links = ["https://www.google.com/", "https://amazon.com/", "https://example.com/", "https://one.one.one.one/", "https://dns.google/"]
    global ipchanger
    global showtext
    global proxy_ips
    global totalproxies
    while True:
        try:
            if "@" in ipchanger:
                proxy = random.choice(proxy_ips)
                proxy = proxy.replace("multihop|", "")
                url = random.choice(links)
                proxy = SOCKSProxyManager("socks5://"+str(proxy))
                check = proxy.request('GET', url, timeout=5.0)
                time.sleep(60)
            else:
                proxy = random.choice(proxy_ips)
                url = random.choice(links)
                proxy = SOCKSProxyManager("socks5://"+str(proxy))
                check = proxy.request('GET', url, timeout=5.0)
                if totalproxies > 5:
                    if totalproxies > 10:
                        if totalproxies > 15:
                            if totalproxies > 20:
                                time.sleep(1)
                            else:
                                time.sleep(3)
                        else:
                            time.sleep(5)
                    else:
                        time.sleep(7)
                else:
                    time.sleep(9)
        except:
            showtext = True
            pproxy_multihop()
            time.sleep(15)

def modules():
    if WHITELIST == "on" or WHITELIST == "On" or WHITELIST == "off" or WHITELIST == "Off":
        fail = False
    else:
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, whitelist\x1B[37m")
        if CHNBLOCK == "on" or CHNBLOCK == "On" or MALWAREBLOCK == "on" or MALWAREBLOCK == "On" or ADBLOCK == "on" or ADBLOCK == "On" or DONOTRACK == "on" or DONOTRACK == "On":
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            if CHNBLOCK == "on" or CHNBLOCK == "On":
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] starting error, --chinablock option cannot work together with --whitelist\x1B[37m")
            elif MALWAREBLOCK == "on" or MALWAREBLOCK == "On":
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] starting error, --malwareblock option cannot work together with --whitelist\x1B[37m")
            elif ADBLOCK == "on" or ADBLOCK == "On":
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] starting error, --adblock option cannot work together with --whitelist\x1B[37m")
            elif DONOTRACK == "on" or DONOTRACK == "On":
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] starting error, --trackblock option cannot work together with --whitelist\x1B[37m")
            elif BLACKLIST == "on" or BLACKLIST == "On" or BLACKLIST == "off" or BLACKLIST == "Off":
                fail = False
                exit(9)
                exit(9)
        if BLACKLIST == "on" or BLACKLIST == "On" or BLACKLIST == "off" or BLACKLIST == "Off":
            fail = False
        else:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] starting error, --blacklist option cannot work together with --whitelist\x1B[37m")
            exit(9)
            exit(9)
    if BLACKLIST == "off" or BLACKLIST == "Off":
        fail = True
    else:
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, block by blacklist\x1B[37m")
    if CHNBLOCK == "on" or CHNBLOCK == "On":
        global chineseip
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, china IP blocker\x1B[37m")
        chineseip = requests.get("https://txthinking.github.io/bypass/chinacidr4.txt").text
        chineseip = chineseip.split()
    if MALWAREBLOCK == "on" or MALWAREBLOCK == "On":
        global malwareblock
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, malware blocker\x1B[37m")
        malwareblock = requests.get("https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.ip").text
        malwareblock = malwareblock.replace("1 day", "")
        malwareblock = malwareblock.replace("2 day", "")
        malwareblock = malwareblock.replace("3 day", "")
        malwareblock = malwareblock.replace(".site", "")
        malwareblock = malwareblock.replace(".com", "")
        malwareblock = malwareblock.replace(".org", "")
        malwareblock = malwareblock.replace(".me", "")
        malwareblock = malwareblock.replace("#", "")
        malwareblock = malwareblock.replace("Q", "")
        malwareblock = malwareblock.replace("W", "")
        malwareblock = malwareblock.replace("E", "")
        malwareblock = malwareblock.replace("R", "")
        malwareblock = malwareblock.replace("T", "")
        malwareblock = malwareblock.replace("Y", "")
        malwareblock = malwareblock.replace("U", "")
        malwareblock = malwareblock.replace("I", "")
        malwareblock = malwareblock.replace("O", "")
        malwareblock = malwareblock.replace("P", "")
        malwareblock = malwareblock.replace("A", "")
        malwareblock = malwareblock.replace("S", "")
        malwareblock = malwareblock.replace("D", "")
        malwareblock = malwareblock.replace("F", "")
        malwareblock = malwareblock.replace("G", "")
        malwareblock = malwareblock.replace("H", "")
        malwareblock = malwareblock.replace("J", "")
        malwareblock = malwareblock.replace("K", "")
        malwareblock = malwareblock.replace("L", "")
        malwareblock = malwareblock.replace("Z", "")
        malwareblock = malwareblock.replace("X", "")
        malwareblock = malwareblock.replace("C", "")
        malwareblock = malwareblock.replace("V", "")
        malwareblock = malwareblock.replace("B", "")
        malwareblock = malwareblock.replace("N", "")
        malwareblock = malwareblock.replace("M", "")
        malwareblock = malwareblock.replace("q", "")
        malwareblock = malwareblock.replace("w", "")
        malwareblock = malwareblock.replace("e", "")
        malwareblock = malwareblock.replace("r", "")
        malwareblock = malwareblock.replace("t", "")
        malwareblock = malwareblock.replace("y", "")
        malwareblock = malwareblock.replace("u", "")
        malwareblock = malwareblock.replace("i", "")
        malwareblock = malwareblock.replace("o", "")
        malwareblock = malwareblock.replace("p", "")
        malwareblock = malwareblock.replace("a", "")
        malwareblock = malwareblock.replace("s", "")
        malwareblock = malwareblock.replace("d", "")
        malwareblock = malwareblock.replace("f", "")
        malwareblock = malwareblock.replace("g", "")
        malwareblock = malwareblock.replace("h", "")
        malwareblock = malwareblock.replace("j", "")
        malwareblock = malwareblock.replace("k", "")
        malwareblock = malwareblock.replace("l", "")
        malwareblock = malwareblock.replace("z", "")
        malwareblock = malwareblock.replace("x", "")
        malwareblock = malwareblock.replace("c", "")
        malwareblock = malwareblock.replace("v", "")
        malwareblock = malwareblock.replace("b", "")
        malwareblock = malwareblock.replace("n", "")
        malwareblock = malwareblock.replace("m", "")
        malwareblock = malwareblock.replace("]", "")
        malwareblock = malwareblock.replace("[", "")
        malwareblock = malwareblock.replace("-", "")
        malwareblock = malwareblock.replace(":", "")
        malwareblock = malwareblock.replace("/", "")
        malwareblock = malwareblock.replace(" ", "")
        malwareblock = malwareblock.split()
    if IPINFO == "on" or IPINFO == "On":
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, advanced logs\x1B[37m")
    if ADBLOCK == "on" or ADBLOCK == "On":
        global adsip
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, ad blocker\x1B[37m")
        adsip = requests.get("https://raw.githubusercontent.com/mishakorzik/mishakorzik.menu.io/master/%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80/ad.txt").text
        adsip = adsip.split()
    if DONOTRACK == "on" or DONOTRACK == "On":
        global donotrack
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, do not track\x1B[37m")
        donotrack = requests.get("https://raw.githubusercontent.com/dibdot/banIP-IP-blocklists/main/adguardtrackers-ipv4.txt").text 
        donotrack = donotrack.split()
    if CONSOLE == "on" or CONSOLE == "On":
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, basic console\x1B[37m")
    if MULTIHOP == "on" or MULTIHOP == "On":
        multihopp_start = threading.Thread(target=pproxy_multihop)
        multihopp_start.start()
        time.sleep(14)
        multihopp_check = threading.Thread(target=multihop_check)
        multihopp_check.start()
        multihopp_changer = threading.Thread(target=set_multihop)
        multihopp_changer.start()
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        print(f"\x1B[35m[\x1B[37m{current_today}{current_time}\x1B[35m] Successfully actived module, multihop\x1B[37m")

now = datetime.now()
current_time = now.strftime(" %H:%M:%S")
current_today = date.today().strftime("%d.%m.%Y /")
if EXPRORE == "off" or EXPRORE == "Off":
    print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] Starting the server and main components\x1B[37m")
modules()
print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] The specified modifications have been launched\x1B[37m")

def stopserver():
    global console_status
    console_status = False
    now = datetime.now()
    current_time = now.strftime(" %H:%M:%S")
    current_today = date.today().strftime("%d.%m.%Y /")
    print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Server console stopped, use CTRL+C for stop server\x1B[37m")
    if EXPRORE == "on" or EXPRORE == "On":
        os.system(f"""pkill -f 'ngrok tcp {PORT} --region={ngrokregion}'""")
    try:
        pid = os.getpid()
        os.system("kill -9 "+str(pid))
    except:
        exit(1)
        exit(1)

def console():
    time.sleep(1)
    while console_status:
        try:
            cmd = input(f"\x1B[32mhe1zen@console\x1B[37m:\x1B[34m~\x1B[37m$ ")
        except EOFError:
            try:
                print("  ")
                cmd = input(f"\x1B[31mhe1zen@console\x1B[37m:\x1B[34m~\x1B[37m$ ")
            except EOFError:
                log.write("---socks5 end of logging---")
                log.close()
                try:
                    pid = os.getpid()
                    os.system("kill -9 "+str(pid))
                except:
                    exit(1)
                    exit(1)
        if cmd == "tunnel":
            v = str(SOCKS)
            p = str(PORT)
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            try:
                loc = requests.get("http://ipwho.is", timeout=5).json()
                city = loc["city"]
                loc = loc["country"]
            except:
                loc = requests.get("https://ipapi.co//json/").json()
                city = loc["city"]
                loc = loc["country_name"]
            if ipchanger == "null":
                try:
                    if sys.platform == 'win32':
                        ips, _ = exprore1.split(":")
                        _, result = sp.getstatusoutput("ping -n 1 "+ip)
                    else:
                        ips, _ = exprore1.split(":")
                        _, result = sp.getstatusoutput("ping -c 1 "+ip)
                    result = result.split()
                    for ms in result:
                        if "time=" in ms:
                            ms = ms.replace("time=", "")
                            ms = ms+"ms"
                            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}, {ms}\x1B[37m")
                            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
                except:
                    print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}\x1B[37m")
                    print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
            elif "multihop" in ipchanger:
                ip = ipchanger.replace("multihop|", "")
                try:
                    locc = requests.get("http://ipwho.is", timeout=4, proxies={"http": "socks5://"+ip}).json()
                    cityy = locc["city"]
                    locc = locc["country"]
                except:
                    try:
                        locc = requests.get("https://ipapi.co//json/", timeout=4, proxies={"http": "socks5://"+ip}).json()
                        cityy = locc["city"]
                        locc = locc["country_name"]
                    except:
                        cityy = "null"
                        locc = "null"
                if "@" in ipchanger:
                    _, proxy = ip.split("@")
                    ip, _ = proxy.split(":")
                    try:
                        if sys.platform == 'win32':
                            ips, _ = exprore1.split(":")
                            _, result2 = sp.getstatusoutput("ping -n 1 "+ips)
                        else:
                            _, result1 = sp.getstatusoutput("ping -c 1 "+ip)
                            _, result2 = sp.getstatusoutput("ping -c 1 "+ips)
                        result1 = result1.split()
                        result2 = result2.split()
                        for ms in result2:
                            if "time=" in ms:
                                ms = ms.replace("time=", "")
                                ms = ms+"ms"
                                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}, {ms}\x1B[37m")
                        for ms in result1:
                            if "time=" in ms:
                                ms = ms.replace("time=", "")
                                ms = ms+"ms"
                                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
                    except:
                        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}\x1B[37m")
                        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
                else:
                    ip, _ = ip.split(":")
                    try:
                        if sys.platform == 'win32':
                            ips, _ = exprore1.split(":")
                            _, result2 = sp.getstatusoutput("ping -n 1 "+ips)
                        else:
                            ips, _ = exprore1.split(":")
                            _, result2 = sp.getstatusoutput("ping -c 1 "+ips)
                        result2 = result2.split()
                        for ms in result2:
                            if "time=" in ms:
                                ms = ms.replace("time=", "")
                                ms = ms+"ms"
                                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}, {ms}\x1B[37m")
                    except:
                        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}\x1B[37m")
                        print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] multihop: {ip} - {locc}, {cityy}\x1B[37m")
                global totalproxies
                total = str(totalproxies)
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] number of proxy servers for multihop: {total}\x1B[37m")
            else:
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] socks{v}: {exprore1}\x1B[37m")
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] localhost: 127.0.0.1:{p} - {loc}, {city}\x1B[37m")
                print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] ipchanger: {ipchanger}\x1B[37m")
        elif cmd == "python":
            import platform
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            ver = str(platform.python_version())
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] python version: {ver}\x1B[37m")
        elif cmd == "ping":
            h = input("host: ")
            os.system("ping -c 5 "+str(h))
        elif cmd == "stop":
            stopserver()
        elif cmd == "system":
            import platform
            print("system: "+platform.system())
        elif cmd == "socks5":
            proxy_south_america = []
            proxy_north_america = []
            proxy_europe = []
            proxy_asia = []
            get = requests.get("https://www.proxyscan.io/api/proxy?country=fr,it,pl,nl,de,uk,at,ua&uptime=50&ping=100&type=socks5&limit=15").json()
            for dat in get:
                ip = dat["Ip"]
                port = dat["Port"]
                try:
                    check = requests.get("https://www.google.com", timeout=3, proxies={"https": "socks5://"+ip+":"+str(port)})
                    proxy_europe.append(ip+":"+str(port))
                except:
                    fail = True
            get = requests.get("https://www.proxyscan.io/api/proxy?country=in,cn,jp,sg,th&uptime=50&ping=400&type=socks5&limit=15").json()
            for dat in get:
                ip = dat["Ip"]
                port = dat["Port"]
                try:
                    check = requests.get("https://www.google.com", timeout=3, proxies={"https": "socks5://"+ip+":"+str(port)})
                    proxy_asia.append(ip+":"+str(port))
                except:
                    fail = True
            get = requests.get("https://www.proxyscan.io/api/proxy?country=br,ar&uptime=50&ping=400&type=socks5&limit=15").json()
            for dat in get:
                ip = dat["Ip"]
                port = dat["Port"]
                try:
                    check = requests.get("https://www.google.com", timeout=3, proxies={"https": "socks5://"+ip+":"+str(port)})
                    proxy_south_america.append(ip+":"+str(port))
                except:
                    fail = True
            get = requests.get("https://www.proxyscan.io/api/proxy?country=us,ca&uptime=50&ping=300&type=socks5&limit=15").json()
            for dat in get:
                ip = dat["Ip"]
                port = dat["Port"]
                try:
                    check = requests.get("https://www.google.com", timeout=3, proxies={"https": "socks5://"+ip+":"+str(port)})
                    proxy_north_america.append(ip+":"+str(port))
                except:
                    fail = True
            print("Europe proxies")
            for show in proxy_europe:
                print(show)
            print(" ")
        elif cmd == "socks4":
            proxy = []
            get = requests.get("https://www.proxyscan.io/api/proxy?country=fr,it,pl,nl,de,uk,at&uptime=50&ping=100&type=socks4&limit=7").json()
            for dat in get:
                ip = dat["Ip"]
                port = dat["Port"]
                proxy.append(ip+":"+str(port))
            for show in proxy:
                print(show)
        elif "proxy" in cmd.lower():
            if MULTIHOP == "off" or MULTIHOP == "Off":
                try:
                    command, server = cmd.split(" --socks5")
                    server = server.replace(" ", "")
                    proxyy(server)
                except:
                    print("unknown usage: "+cmd)
                    print("command: proxy --socks5 <ip:port>")
                    print("command: proxy --socks5 auto")
                    print("command: proxy --socks5 off")
            else:
                print("cmd: command not found: "+cmd)
        elif cmd == "data":
            try:
                global data1
                print(data1)
            except:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] failed to retrieve data because no recent connections were found\x1B[37m")
        elif "multihop" in cmd:
            if MULTIHOP == "on" or MULTIHOP == "On":
                if "--change" in cmd:
                    global showtext
                    showtext = True
                    pproxy_multihop()
                elif "--info" in cmd:
                    proxy = ipchanger.replace("multihop|", "")
                    myip = requests.get("https://api.ipify.org").text
                    print("notice: \x1B[34mmultihop proxy is much more secure and anonymous\x1B[37m")
                    print("multihop proxy: \x1B[33mperson\x1B[37m >> "+myip+" >> "+proxy+" >> \x1B[33minternet\x1B[37m")
                    print("             your IP -------^                      ^----- 2nd proxy IP")
                    print(" ")
                    print("notice: \x1B[34mnormal proxy is less secure than multihop proxy\x1B[37m")
                    print("default proxy: \x1B[33mperson\x1B[37m >> "+myip+" >> \x1B[33minternet\x1B[37m")
                    print("             your IP ------^")
                else:
                    print("unknwon usage: "+cmd)
                    print("command: multihop --info")
                    print("command: multihop --change")
            else:
                print("cmd: command not found: "+cmd)
        elif cmd == "conn":
            cn = str(connections)
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            kb = str(kbytesdata)
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] all connections that have been made: {cn}\x1B[37m")
            print(f"\x1B[34m[\x1B[37m{current_today}{current_time}\x1B[34m] all sent data in KBytes: {kb}\x1B[37m")
        elif cmd == "help":
            print("data    : get encoded last data")
            if MULTIHOP == "off" or MULTIHOP == "Off":
                print("proxy   : change IP address by proxy")
            else:
                print("multihop: show multihop settings")
            print("socks5  : get socks5 proxies from list")
            print("socks4  : get socks4 proxies from list")
            print("system  : show system info")
            print("python  : show python version")
            print("tunnel  : show current tunnel")
            print("stop    : stop proxy server")
            print("conn    : show connections status")
            print("ping    : hing ping writed host")
        else:
            print("cmd: command not found: "+cmd)

class Proxy:
    def __init__(self):
        self.username = args.username
        self.password = args.password

    def handle_client(self, connection):
        global bind_address
        global address
        global version
        global nmethods
        global methods
        global domain
        global address_type
        global bind_address
        global port
        global cmd
        try:
            version, nmethods = connection.recv(2)
        except:
            connection.close()

        try:
            methods = self.get_available_methods(nmethods, connection)
        except:
            connection.close()

        if AUTH == "off" or AUTH == "Off":
            # accept no auth
            try:
                connection.sendall(bytes([VERSION, 0]))
            except:
                connection.close()
                return
        elif AUTH == "on" or AUTH == "On":
            try:
                # accept only USERNAME/PASSWORD auth
                if 2 not in set(methods):
                    connection.close()
                    return
                connection.sendall(bytes([VERSION, 2]))
                if not self.verify_credentials(connection):
                    now = datetime.now()
                    current_time = now.strftime(" %H:%M:%S")
                    current_today = date.today().strftime("%d.%m.%Y /")
                    print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed, the user wrote the wrong password or username\x1B[37m")
                    return
            except:
                fail = True

        try:
            version, cmd, _, address_type = connection.recv(4)
        except:
            connection.close()

        try:
            if address_type == 1:  # IPv4
                domain = ""
                address = socket.inet_ntoa(connection.recv(4))
            elif address_type == 3:  # Domain name
                domain = ""
                domain_length = connection.recv(1)[0]
                address = connection.recv(domain_length)
                domain = address.decode("utf-8")
                address = socket.gethostbyname(address)
            elif address_type == 4:  # IPv6
                domain = ""
                address = socket.inet_ntop(connection.recv(16))
        except:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            if address_type == 1:
                log.write(f"connection canceled, failed to get IPv4\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection canceled, failed to get IPv4\x1B[37m")
            elif address_type == 3:
                log.write(f"connection canceled, failed to get domain\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection canceled, failed to get domain\x1B[37m")
            elif address_type == 4:
                log.write(f"connection canceled, failed to get IPv6\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection canceled, failed to get IPv6\x1B[37m")
            else:
                log.write(f"connection canceled, unknown address type\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection canceled, unknown address type\x1B[37m")
        try:
            port = int.from_bytes(connection.recv(2), 'big', signed=False)
        except:
            connection.close()
        if cmd == 1:
            global anti
            global connections
            global ipchanger
            if BLACKLIST == "off" or BLACKLIST == "Off":
                fail = False
            else:
                try:
                    find = os.path.isfile(BLACKLIST)
                    if find == True:
                        rban = open(BLACKLIST, "r")
                        ban = rban.read()
                        ban = ban.split()
                        rban.close()
                    else:
                        now = datetime.now()
                        current_time = now.strftime(" %H:%M:%S")
                        current_today = date.today().strftime("%d.%m.%Y /")
                        print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] blacklist error, file not found!\x1B[37m")
                        exit(4)
                        exit(4)
                    for check in ban:
                        if check in address:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (blacklist): {address}:{port}\x1B[37m")
                            connection.close()
                except:
                    fail = True
            if WHITELIST == "off" or WHITELIST == "Off":
                fail = False
            else:
                try:
                    find = os.path.isfile(WHITELIST)
                    if find == True:
                        rallow = open(WHITELIST, "r")
                        allow = rallow.read()
                        allow = allow.split()
                        rallow.close()
                    else:
                        now = datetime.now()
                        current_time = now.strftime(" %H:%M:%S")
                        current_today = date.today().strftime("%d.%m.%Y /")
                        print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] blacklist error, file not found!\x1B[37m")
                        exit(4)
                        exit(4)
                    for check in allow:
                         if check == address:
                             fail = True
                         else:
                             print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (whitelist): {address}:{port}\x1B[37m")
                             log.write(f"connection closed (whitelist): {address}:{port}\n")
                             reply = self.generate_failed_reply(address_type, 5)
                             connection.close()
                except:
                    fail = True
            if ADBLOCK == "on" or ADBLOCK == "On":
                try:
                    for check in adsip:
                        if check == address:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (adblock): {address}:{port}\x1B[37m")
                            log.write(f"connection closed (adblock): {address}:{port}\n")
                            reply = self.generate_failed_reply(address_type, 5)
                            connection.close()
                except:
                    stop = True
            if MALWAREBLOCK == "on" or MALWAREBLOCK == "On":
                try:
                     for check in malwareblock:
                         if check == address:
                             now = datetime.now()
                             current_time = now.strftime(" %H:%M:%S")
                             current_today = date.today().strftime("%d.%m.%Y /")
                             print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (malwareblock): {address}:{port}\x1B[37m")
                             log.write(f"connection closed (malwareblock): {address}:{port}\n")
                             reply = self.generate_failed_reply(address_type, 5)
                             connection.close()
                except:
                    stop = True
            if DONOTRACK == "on" or DONOTRACK == "On":
                try:
                    for check in donotrack:
                        if check == address:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (trackblock): {address}:{port}\x1B[37m")
                            log.write(f"connection closed (trackblock): {address}:{port}\n")
                            connection.close()
                except:
                    stop = True
            if CHNBLOCK == "on" or CHNBLOCK == "On":
                try:
                    for check in chineseip:
                        if check == address:
                            now = datetime.now()
                            current_time = now.strftime(" %H:%M:%S")
                            current_today = date.today().strftime("%d.%m.%Y /")
                            print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed (chnblock): {address}:{port}\x1B[37m")
                            log.write(f"connection closed (chnblock): {address}:{port}\n")
                            connection.close()
                except:
                    stop = True
            try:
                if ipchanger == "null":
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.settimeout(5)
                    remote.connect((address, port))
                elif "|" in ipchanger:
                    if "@" in ipchanger:
                        _, ipdat = ipchanger.split("|")
                        auth, vpn = ipdat.split("@")
                        username, password = auth.split(":")
                        ipp, pp = vpn.split(":")
                        pp = int(pp)
                        remote = socks.socksocket()
                        remote.set_proxy(socks.SOCKS5, ipp, pp, True, username, password)
                        remote.settimeout(7)
                        remote.connect((address, port))
                    else:
                        _, ipdat = ipchanger.split("|")
                        ipp, pp = ipdat.split(":")
                        remote = socks.socksocket()
                        remote.set_proxy(socks.SOCKS5, ipp, int(pp))
                        remote.settimeout(7)
                        remote.connect((address, port))
                else:
                    ipp, pp = ipchanger.split(":")
                    remote = socks.socksocket()
                    remote.set_proxy(socks.SOCKS5, ipp, int(pp))
                    remote.settimeout(9)
                    remote.connect((address, port))
            except TimeoutError:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection timeout {address}:{port}\x1B[37m")
                log.write(f"connection timeout {address}:{port}\n")
            except ConnectionRefusedError:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                if address == "0.0.0.0" or address == "127.0.0.1":
                    pass
                else:
                    print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection refused {address}:{port}\x1B[37m")
                    log.write(f"connection refused {address}:{port}\n")
            except OSError:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                try:
                    address = address.decode("utf-8")
                except:
                    pass
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed, no route to host {address}:{port}\x1B[37m")
                log.write(f"connection closed, no route to host {address}:{port}\n")
            except socket.gaierror:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed, no address associated with hostname {address}:{port}\x1B[37m")
                log.write(f"connection closed, no address associated with hostname {address}:{port}\n")
            except TypeError:
                pass
            except socks.ProxyConnectionError:
                pass
            if IPINFO == "on" or IPINFO == "On":
                connections = connections + 1
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                try:
                     if domain == "":
                         (dat, _, _) = socket.gethostbyaddr(address)
                         print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] Client connected to {address}:{port} - {dat}\x1B[37m")
                         log.write(f"client connected to {address}:{port}\n")
                     else:
                         print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] Client connected to {domain}:{port} - {dat}\x1B[37m")
                         log.write(f"client connected to {domain}:{port}\n")
                except:
                     print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] Client connected to {address}:{port} - unknown\x1B[37m")
                     log.write(f"client connected to {address}:{port}\n")
            else:
                connections = connections + 1
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                try:
                    if domain == "":
                        print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] Client connected to {address}:{port}\x1B[37m")
                        log.write(f"client connected to {address}:{port}\n")
                    else:
                        print(f"\r\x1B[33m[\x1B[37m{current_today}{current_time}\x1B[33m] Client connected to {domain}:{port}\x1B[37m")
                        log.write(f"client connected to {domain}:{port}\n")
                except UnboundLocalError:
                    fail = True
            try:
                bind_address = remote.getsockname()
            except OSError:
                connection.close()
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
        else:
            connection.close()
        try:
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            reply = b''.join([
                VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
            connection.sendall(reply)
            if reply[1] == 0 and cmd == 1:
                # establish data exchange
                self.exchange_loop(connection, remote, address, port)
        except:
            connection.close()
        connection.close()

    def exchange_loop(self, client, remote, address, port):
        while True:
            global kbytesdata
            global data1
            global data2
            global dar
            global c
            global r
            r, w, e = select.select([client, remote], [], [])
            try:
                if client in r:
                    data1 = client.recv(4096)
                    c = remote.send(data1)
                    if c <= 0:
                        break
                    else:
                        dar = float(len(data1))
                        dar = float(dar/1024)
                        dar = "%.3s" % (str(dar))
                        kbytesdata = kbytesdata + float(dar)
            except:
                fail = True

            try:
                if remote in r:
                    data2 = remote.recv(4096)
                    r = client.send(data2)
                    if r <= 0:
                        break
                    else:
                        dar = float(len(data1))
                        dar = float(dar/1024)
                        dar = "%.3s" % (str(dar))
                        kbytesdata = kbytesdata + float(dar)
            except ConnectionResetError:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                log.write(f"client connection to host reset\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Client connection to host reset\x1B[37m")
            except ConnectionAbortedError:
                now = datetime.now()
                current_time = now.strftime(" %H:%M:%S")
                current_today = date.today().strftime("%d.%m.%Y /")
                log.write(f"client connection to host aborted\n")
                print(f"\r\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Client connection to host aborted\x1B[37m")
            except OSError:
                fail = True
            except TypeError:
                fail = True

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = ord(connection.recv(1)) # should be 1

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True

        # failure, status != 0
        try:
            response = bytes([version, 0xFF])
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Connection closed, invalid auth data\x1B[37m")
            connection.sendall(response)
            connection.close()
            return False
        except:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Auth error, client send invalid auth data\x1B[37m")

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        global console_status
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 6)
        try:
            s.bind((host, port))
            s.listen(LISTEN)
        except:
            if ngrokregion == "eu" or ngrokregion == "us" or ngrokregion == "na" or ngrokregion == "sa" or ngrokregion == "in" or ngrokregion == "jp" or ngrokregion == "ap" or ngrokregion == "au":
                os.system(f"""pkill -f 'ngrok tcp {PORT} --region={ngrokregion}'""")
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Address already in use, try another port or address\x1B[37m")
            console_status = False
            exit(1)
            exit(1)
        p = str(PORT)
        l = str(LISTEN)
        v = str(VERSION)
        now = datetime.now()
        current_time = now.strftime(" %H:%M:%S")
        current_today = date.today().strftime("%d.%m.%Y /")
        if EXPRORE == "on" or EXPRORE == "On":
            print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] You socks ip address (ngrok): {exprore1}\x1B[37m")
        print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] You socks ip address (localhost): {host}:{p}\x1B[37m")
        if AUTH == "on" or AUTH == "On":
            print(f"""\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] Username: '{self.username}', password: '{self.password}', version: socks{v}\x1B[37m""")
        print(f"\x1B[32m[\x1B[37m{current_today}{current_time}\x1B[32m] The maximum number of connections is {l}\x1B[37m")
        console_status = True
        print(" ")
        try:
            while True:
                conn, addr = s.accept()
                conn.settimeout(10)
                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.start()
                time.sleep(0.4)
        except KeyboardInterrupt:
            now = datetime.now()
            current_time = now.strftime(" %H:%M:%S")
            current_today = date.today().strftime("%d.%m.%Y /")
            print(f"\n\x1B[31m[\x1B[37m{current_today}{current_time}\x1B[31m] Keyboard Interrupt! Stopping proxy server\x1B[37m")
            console_status = False
            if EXPRORE == "on" or EXPRORE == "On" or EXPRORE == "True" or EXPRORE == "true":
                os.system(f"""pkill -f 'ngrok tcp {PORT} --region={ngrokregion}'""")
            log.write("---socks5 end of logging---")
            log.close()
            try:
                pid = os.getpid()
                os.system("kill -9 "+str(pid))
            except:
                exit(1)
                exit(1)

if __name__ == "__main__":
    if BLACKLIST == "off" or BLACKLIST == "Off":
        malware = "off"
    else:
        fail = True
    if CONSOLE == "on" or CONSOLE == "On" or CONSOLE == "ON" or CONSOLE == "True" or CONSOLE == "true":
        proxy_console = threading.Thread(target=console)
        proxy_console.start()
    proxy = Proxy()
    proxy.run("127.0.0.1", PORT)

