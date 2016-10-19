#!/opt/opsware/agent/bin/python
#title           :ipa.py
#description     :Automate IP address management in Migration.
#author          :Stanimir Kozarev
#date            :201610.20
#version         :0.2
#usage           :python ipa.py
#notes           :
#python_version  :2.7.3
#==============================================================================

import sys
import os
import re
import time
import logging
import inspect
import traceback
import platform
import pprint
from subprocess import Popen, PIPE
from subprocess import call
import ipaddr
import argparse

parser = argparse.ArgumentParser(description = 'Set the Network IP Address')
parser.add_argument('--nicname', default = 'eth0', help='network adapter name')
parser.add_argument('--nicip', default = '192.168.0.1', help='IP address')
parser.add_argument('--nicmask', default = '255.255.255.0', help='IP mask')
parser.add_argument('--nicgw', nargs='?', help='IP gateway')
parser.add_argument('--niclabel', nargs='?', help='configure interface label, optional')
parser.add_argument('--dnsips', nargs='*', help='list of DNS servers for a given interface separated by space, optional')
parser.add_argument('--dnslocal', nargs='*', help='configure local DNS domain name, optional')
parser.add_argument('--dnssuffixes', nargs='*', help='configure DNS Domain Search Suffixes, optional')
parser.add_argument('--regdns', action='store_true', help='register NIC in DNS, optional')
parser.add_argument('--routenet', nargs='?', help='static route network ip')
parser.add_argument('--routemask', nargs='?',help='static route network mask')
parser.add_argument('--routegw', nargs='?', help='static route gateway')
parser.add_argument('--defroute', nargs='?', help='default route')
parser.add_argument('--loglevel', default = 'INFO', help='FATAL, ERROR, WARNING, INFO, DEBUG')
parser.add_argument('--logfile', default = 'ipa.log', help='Logfile to store messages (Default: ipa.log)')
parser.add_argument('--quiet', action='store_true', help='Do not print logging to stdout')

class Interface(object):
    ''' Class representing a network device. '''

    def __init__(self, argshash):
        # OS version
        is_windows=(platform.system().lower().find("win") > -1)
        is_redhat=(platform.linux_distribution()[0].lower().find("red hat") > -1)
        is_suse=(platform.linux_distribution()[0].lower().find("suse") > -1)		
        if is_windows:
            self.ostype = "windows"
        elif is_redhat:
            self.ostype = "redhat"
        else:
            self.ostype = "suse"
        # Properties
        self.nicname = argshash.get("nicname", "eth0")			# default = 'eth0'
        self.nicip = argshash.get("nicip", "192.168.0.1")		# default = '192.168.0.1
        self.nicmask = argshash.get("nicmask", "255.255.255.0")	# default = '255.255.255.0'
        self.nicgw = argshash.get("nicgw")						# opt
        self.niclabel = argshash.get("niclabel")				# opt
        self.dnsips = argshash.get("dnsips")					# opt
        self.dnslocal = argshash.get("dnslocal")			    # opt      
        self.dnssuffixes = argshash.get("dnssuffixes")			# opt
        self.regdns = argshash.get("regdns", False)				# default = False
        self.routenet = argshash.get("routenet")				# opt
        self.routemask = argshash.get("routemask")				# opt
        self.routegw = argshash.get("routegw")					# opt
        self.defroute = argshash.get("defroute")				# opt

    def __repr__(self):
        return "<%s %s at 0x%x>" % (self.__class__.__name__, self.nicname, id(self))

    @staticmethod
    def win_cmd(cmdLine):
        proc = Popen(cmdLine, universal_newlines=True, stderr=PIPE, stdout=PIPE, shell=True)
        (stdout, stderr) = proc.communicate()
        if proc.returncode != 0:
            logging.info("The command failed with code: %d error: %s", proc.returncode, stderr)
            raise RuntimeError(stderr + stdout)
        else :
            logging.info("Command output: %s ", stdout)
        return stdout

    @staticmethod
    def add_subjoin(reg, trgfile, subjointxt, addline):
        with open(trgfile, "r") as f:
            filetxt = f.read()
            f.close()
        if re.search(reg, filetxt, re.MULTILINE): # subjoin text to line
            print "SUBJOIN"
            cmdLine = "sed -i '/" + reg + "/s/$/ " + subjointxt + " /' " + trgfile
            os.system(cmdLine)
        else:   # add new configuration line
            print "ADD NEW LINE"
            with open(trgfile, "a") as f:
                f.write(addline)
                f.close()
        return

    def set_ip(self):
        netrestart = False	# request or not network service restart
        if self.ostype == "windows":
            try:
                cmdLine = 'netsh int ip set address "' + self.nicname + '" static ' + self.nicip + ' ' + self.nicmask + (' ' + self.nicgw if self.nicgw else '')
                cmdout = Interface.win_cmd(cmdLine)
                time.sleep(3)
                cmdLine = 'netsh int ip show addresses "' + self.nicname + '"' 
                cmdout = Interface.win_cmd(cmdLine)	
            except:
                print "Something Didn't Work with IP setup"
                raise RuntimeError('The command failed')
        if self.ostype == "redhat":
            try:
                print "Red Had set IP"
                devfile = r'/etc/sysconfig/network-scripts/ifcfg-' + self.nicname
                with open(devfile, "w") as f:
                    f.write('DEVICE=' + self.nicname + '\n')
                    f.write('ONBOOT=yes\n')
                    f.write('USERCTL=no\n')
                    f.write('BOOTPROTO=static\n')
                    f.write('IPADDR=' + self.nicip + '\n')
                    f.write('NETMASK=' + self.nicmask + '\n')
                    f.write('NM_CONTROLLED=no\n')
                    f.close()
                netrestart = True
            except:
                print "Something Didn't Work in Red Had with IP setup"
                raise RuntimeError('The command failed')
        if self.ostype == "suse":
            try:
                print "SUSE set IP"
                devfile = '/etc/sysconfig/network/ifcfg-' + self.nicname
                with open(devfile, "w") as f:
                    f.write('DEVICE=' + self.nicname + '\n')
                    f.write('ONBOOT=yes\n')
                    f.write('USERCTL=no\n')
                    f.write('BOOTPROTO=static\n')
                    f.write('IPADDR=' + self.nicip + '\n')
                    f.write('NETMASK=' + self.nicmask + '\n')
                    f.write('NM_CONTROLLED=no\n')
                    f.write('STARTMODE=auto\n')
                    f.close()
                netrestart = True
            except:
                print "Something Didn't Work in SUSE with IP setup"
                raise RuntimeError('The command failed')
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def add_dnssrv(self):
        netrestart = False	# request or not network service restart
        if self.dnsips:
            if self.ostype == "windows":
                try:
                    logging.info("DNS list: %s", self.dnsips)
                    if self.regdns is True:
                        logging.info("Register NIC in DNS")
                        regdns = "primary"
                    else:
                        logging.info("Will not register NIC in DNS")
                        regdns = "none"
                    logging.info("Add first DNS server")
                    cmdLine = 'netsh int ip set dns "' + self.nicname + '" static ' + self.dnsips[0] + ' ' + regdns
                    cmdout = Interface.win_cmd(cmdLine)
                    dnscount = int(self.dnsips.__len__())
                    for i in range(1, dnscount):
                        logging.info("Adding next %d DNS servers: %s ", i, self.dnsips[i])
                        if self.dnsips[i]:
                            cmdLine = 'netsh int ip add dns "' + self.nicname + '" ' + self.dnsips[i] + ' index=' + str(i+1)
                            cmdout = Interface.win_cmd(cmdLine)
                except:
                    print "Something Didn't Work in DNS configuration"
                    raise RuntimeError('The command failed')
            if self.ostype == "redhat":
                try:
                    print "Red Had set DNS"
                    dnsfile='/etc/resolv.conf'
                    devfile = r'/etc/sysconfig/network-scripts/ifcfg-' + self.nicname
                    dnscount = int(self.dnsips.__len__()) + 1
                    for i in range(1, dnscount):
                        logging.info("Adding %d DNS server: %s ", i, self.dnsips[i-1])
                        if self.dnsips[i-1]:
                            with open(dnsfile, "a") as f1:
                                addline = 'nameserver   ' + self.dnsips[i-1] + '\n'
                                f1.write(addline)
                            with open(devfile, "a") as f2:
                                addline = 'DNS' + str(i) + '=' + self.dnsips[i-1] + '\n'
                                f2.write(addline)
                    f1.close()
                    f2.close()
                    netrestart = True
                except:
                    print "Something Didn't Work in Red Had DNS configuration"
                    raise RuntimeError('The command failed')
            if self.ostype == "suse":
                try:
                    print "SUSE set DNS"
                    dnsfile='/etc/resolv.conf'
                    dnsipslist = ' '.join(self.dnsips)
                    dnscount = int(self.dnsips.__len__()) + 1
                    for i in range(1, dnscount):
                        logging.info("Adding %d DNS server: %s ", i, self.dnsips[i-1])
                        if self.dnsips[i-1]:
                            with open(dnsfile, "a") as f:
                                addline = 'nameserver   ' + self.dnsips[i-1] + '\n'
                                f.write(addline)
                                f.close()
                    netcfgfile = r'/etc/sysconfig/network/config' 
                    os.system("sed  -i 's/NETCONFIG_DNS_STATIC_SERVERS=/###NETCONFIG_DNS_STATIC_SERVERS=/' " + netcfgfile)
                    with open(netcfgfile, "a") as f:
                        addline = 'NETCONFIG_DNS_STATIC_SERVERS="' + dnsipslist + '"\n'
                        f.write(addline)
                        f.close()
                    netrestart = True
                except:
                    print "Something Didn't Work in SUSE DNS configuration"
                    raise RuntimeError('The command failed')
        else:
            logging.info("DNS list is empty")
            cmdout = "DNS list is empty"
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def add_dnslocal(self):
        netrestart = False	# request or not network service restart
        if self.dnslocal:
            if self.ostype == "windows":
                try:
                    dnslocal = ""
                    if hasattr(self.dnslocal, "__iter__"):
                        dnslocal = self.dnslocal[0]
                    else:
                        dnslocal = self.dnslocal
                    logging.info("Set local DNS suffix: %s", dnslocal)
                    cmdLine = 'getmac /fo csv /v /NH'
                    cmdout = Interface.win_cmd(cmdLine)
                    schstr = self.nicname + '(.*)'
                    match = re.search(schstr, cmdout, re.MULTILINE)
                    if hasattr(match, 'group'):
                        if match.group(1):
                            intGUID = re.search(r"({.*})", match.group(1))
                    cmdLine = 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\\' + intGUID.group(1) + '" /v "Domain" /d "' + dnslocal + '" /f'
                    cmdout = Interface.win_cmd(cmdLine)
                except:
                    print "Something Didn't Work in DNS suffixes configuration"
                    raise RuntimeError('The command failed')
            if self.ostype == "redhat":
                try:
                    print "Set local DNS in Red Had"
                    dnslocallist = ' '.join(self.dnslocal)
                    dnsfile = '/etc/resolv.conf'
                    addline = 'domain ' + dnslocallist + '\n'
                    Interface.add_subjoin('domain ', dnsfile, dnslocallist , addline)
                    netrestart = True
                except:
                    print "Set local DNS in Red Had failed"
                    raise RuntimeError('The command failed')
            if self.ostype == "suse":
                try:
                    print "Set local DNS in SUSE"
                    dnslocallist = ' '.join(self.dnslocal)
                    dnsfile = '/etc/resolv.conf'
                    addline = 'domain ' + dnslocallist + '\n'
                    Interface.add_subjoin('domain ', dnsfile, dnslocallist , addline)
                    netrestart = True
                except:
                    print "Set local DNS in SUSE failed"
                    raise RuntimeError('The command failed')
        else:
            logging.info("Local DNS list is empty")
            cmdout = "Local DNS list is empty"
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def add_dnssuff(self):
        netrestart = False	# request or not network service restart
        if self.dnssuffixes:
            if self.ostype == "windows":
                try:
                    logging.info("DNS suffixes list: %s", self.dnssuffixes)
                    cmdLine = 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "SearchList"'
                    cmdout = Interface.win_cmd(cmdLine)
                    dnssuff = re.search(r"SearchList\s+REG_SZ\s+([\w\.\,\ ]+)", cmdout)
                    curdnssuff = str(dnssuff.group(1)).strip()
                    if curdnssuff:
                        curdnssuff = dnssuff.group(1)
                        dnssuffixes = ",".join(str(bit) for bit in self.dnssuffixes) + (', ' + curdnssuff if curdnssuff else '')
                    else:
                        dnssuffixes = ",".join(str(bit) for bit in self.dnssuffixes)
                    cmdLine = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "SearchList" /d "' + dnssuffixes + '" /f'
                    cmdout = Interface.win_cmd(cmdLine)
                except:
                    print "Something Didn't Work in DNS suffixes configuration"
                    raise RuntimeError('The command failed')
            if self.ostype == "redhat":
                try:
                    print "Set DNS suffixes in Red Had"
                    dnssufflist = ' '.join(self.dnssuffixes)
                    dnsfile = '/etc/resolv.conf'
                    addline = 'search ' + dnssufflist + '\n'
                    Interface.add_subjoin('search', dnsfile, dnssufflist , addline)
                    netrestart = True
                except:
                    print "Set DNS suffixes in Red Had failed"
                    raise RuntimeError('The command failed')
            if self.ostype == "suse":
                try:
                    print "Set DNS suffixes in SUSE"
                    dnssufflist = ' '.join(self.dnssuffixes)
                    dnsfile = '/etc/resolv.conf'
                    addline = 'search ' + dnssufflist + '\n'
                    Interface.add_subjoin('search', dnsfile, dnssufflist , addline)
                    netcfgfile = r'/etc/sysconfig/network/config' 
                    os.system("sed  -i 's/NETCONFIG_DNS_STATIC_SEARCHLIST=/###NETCONFIG_DNS_STATIC_SEARCHLIST=/' " + netcfgfile)
                    with open(netcfgfile, "a") as f:
                        addline = 'NETCONFIG_DNS_STATIC_SEARCHLIST="' + dnssufflist + '"\n'
                        f.write(addline)
                        f.close()
                    netrestart = True
                except:
                    print "Set DNS suffixes in SUSE failed"
                    raise RuntimeError('The command failed')
        else:
            logging.info("DNS suffixes list is empty")
            cmdout = "DNS suffixes list is empty"
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def add_route(self):
        netrestart = False	# request or not network service restart
        if self.routenet and self.routemask and self.routegw:
            if self.ostype == "windows":
                try:
                    cmdLine = 'route add ' + self.routenet + ' mask ' + self.routemask + ' ' + self.routegw + ' -p'
                    cmdout = Interface.win_cmd(cmdLine)
                    logging.info("Added route %s with netmask %s and gateway %s", self.routenet, self.routemask, self.routegw)
                except:
                    print "Something Didn't Work with adding static route"
                    raise RuntimeError('The command failed')
            if self.ostype == "redhat":
                try:
                    print "Red Hat add static route"
                    net_preffix =  ipaddr.IPv4Network(self.routenet + '/' + self.routemask)
                    print net_preffix.prefixlen
                    routefile = r'/etc/sysconfig/network-scripts/route-' + self.nicname
                    with open(routefile, "a") as f:
                        addline = self.routenet + '/' + str(net_preffix.prefixlen) + ' via ' + self.routegw + '\n'
                        f.write(addline)
                        f.close()
                except:
                    print "Something Didn't Work in Red Had with adding static route"
                    raise RuntimeError('The command failed')
            if self.ostype == "suse":
                try:
                    print "SUSE  add static route"
                    routefile = r'/etc/sysconfig/network/routes'
                    with open(routefile, "a") as f:
                        addline = self.routenet + ' ' + self.routemask + ' ' + self.routegw + '\n'
                        f.write(addline)
                        f.close()
                except:
                    print "Something Didn't Work in SUSE with adding static route"
                    raise RuntimeError('The command failed')
        else:
            logging.info("Missing network, mask or gateway argument of the static route")
            cmdout = "Missing network, mask or gateway argument of the static route"  
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def ch_defroute(self):
        netrestart = False	# request or not network service restart
        if self.defroute:
            if self.ostype == "windows":
                try:
                    cmdLine = 'route add 0.0.0.0 mask 0.0.0.0 ' + self.defroute + ' /p'
                    cmdout = Interface.win_cmd(cmdLine)
                    cmdLine = 'route print 0.0.0.0'
                    cmdout = Interface.win_cmd(cmdLine)
                    for defrt in re.finditer(r"(?:0\.){3}0\s*(?:0\.){3}0\s+(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", cmdout):
                        if str(self.defroute).strip() == str(defrt.group(1)).strip():
                            logging.info("Keep new default route.")
                        else:
                            cmdLine = 'route delete 0.0.0.0 mask 0.0.0.0 ' + str(defrt.group(1)).strip()
                            cmdout = Interface.win_cmd(cmdLine)
                    logging.info("The default route has been changed to: %s", self.defroute)
                except:
                    print "Something Didn't Work with changing the default route"
                    raise RuntimeError('The command failed')
            if self.ostype == "redhat":
                try:
                    print "Changing the default route in Red Hat"
                    devfile = r'/etc/sysconfig/network-scripts/ifcfg-' + self.nicname
                    os.system("sed -i 's/GATEWAY.*//g' " + devfile)
                    with open(devfile, "a") as f:
                        addline = 'GATEWAY=' + self.defroute + '\n'
                        f.write(addline)
                        f.close()
                    netcfgfile = r'/etc/sysconfig/network'
                    os.system("sed -i 's/GATEWAY.*//g' " + netcfgfile)
                    with open(netcfgfile, "a") as f:
                        addline = 'GATEWAY=' + self.defroute + '\n'
                        f.write(addline)
                        f.close()
                except:
                    print "Something Didn't Work in Red Had with changing the default route"
                    raise RuntimeError('The command failed')
            if self.ostype == "suse":
                try:
                    print "Changing the default route in SUSE"
                    routefile = r'/etc/sysconfig/network/routes'
                    os.system("sed -i 's/default.*//g' " + routefile)
                    with open(routefile, "a") as f:
                        addline = 'default ' + self.defroute + ' - -\n'
                        f.write(addline)
                        f.close()
                except:
                    print "Something Didn't Work in SUSE with changing the default route"
                    raise RuntimeError('The command failed')
        else:
            logging.info("The default route has not been changed")
            cmdout = "The default route has not been changed"           
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

    def ch_nicname(self):
        netrestart = False	# request or not network service restart
        if self.ostype == "windows":
            try:
                if self.niclabel:
                    cmdLine = 'netsh int set interface name="' + self.nicname + '"  newname="' + self.niclabel + '"'
                    cmdout = Interface.win_cmd(cmdLine)
                    logging.info("The NIC label was changed to: %s", self.niclabel)
                else:
                    logging.info("NIC has retained its name")
            except:
                print "Something Didn't Work with changing the interface name"
                raise RuntimeError('The command failed')
        if self.ostype == "redhat":
            try:
                print "Changing the interface name in Red Had"
            except:
                print "Something Didn't Work with changing the interface name in Red Had"
                raise RuntimeError('The command failed')
        if self.ostype == "suse":
            try:
                print "Changing the interface name in SUSE"
            except:
                print "Something Didn't Work with changing the interface name in SUSE"
                raise RuntimeError('The command failed')
        try:
            cmdout
        except NameError:
            cmdout = None
        defout = {'cmdout': cmdout, 'netrestart': netrestart}
        return defout

def main():
    levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    # Get the command line arguments
    args = parser.parse_args()
    argsdict = vars(args)

    loglevel = levels.get(args.loglevel, logging.NOTSET)
    logging.basicConfig(
        level= args.loglevel,
        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        datefmt='%m-%d %H:%M',
        filename= args.logfile,
        filemode='a')

    root = logging.getLogger()
    if args.quiet is False: 
        console = logging.StreamHandler()
        console.setLevel(args.loglevel)
        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        console.setFormatter(formatter)
        root.addHandler(console)

    logging.info("Automate IP Address Management")
    logging.info("==============================")
    logging.info(pprint.pprint(vars(args)))	

    nic = Interface(argsdict)

    netrestart = False	# request or not network service restart

    # Set IP Data
    set_ip = nic.set_ip()
    print(set_ip)
    logging.info("Add set IP command output is: [ %s ] and restart requirements is %s", set_ip.get("cmdout"), set_ip.get("netrestart"))
    if set_ip.get("netrestart"): netrestart = True

    # Add DNS Servers
    add_dnssrv = nic.add_dnssrv()
    print(add_dnssrv)
    logging.info("Add DNS servers command output is: [ %s ] and restart requirements is %s", add_dnssrv.get("cmdout"), add_dnssrv.get("netrestart"))
    if add_dnssrv.get("netrestart"): netrestart = True

    # Add Local DNS Suffix
    add_dnslocal = nic.add_dnslocal()
    print(add_dnslocal)
    logging.info("Add DNS suffixes command output is: [ %s ] and restart requirements is %s", add_dnslocal.get("cmdout"), add_dnslocal.get("netrestart"))
    if add_dnslocal.get("netrestart"): netrestart = True
    
    # Add DNS Suffixes
    add_dnssuff = nic.add_dnssuff()
    print(add_dnssuff)
    logging.info("Add DNS suffixes command output is: [ %s ] and restart requirements is %s", add_dnssuff.get("cmdout"), add_dnssuff.get("netrestart"))
    if add_dnssuff.get("netrestart"): netrestart = True

    # Add Static Route Servers
    add_route = nic.add_route()
    print(add_route)
    logging.info("Add route command output is: [ %s ] and restart requirements is %s", add_route.get("cmdout"), add_route.get("netrestart"))
    if add_route.get("netrestart"): netrestart = True

    # Change Default Route
    ch_defroute = nic.ch_defroute()
    print(ch_defroute)
    logging.info("Change default route command output is: [ %s ] and restart requirements is %s", ch_defroute.get("cmdout"), ch_defroute.get("netrestart"))
    if ch_defroute.get("netrestart"): netrestart = True

    # Change Interface Name
    ch_nicname = nic.ch_nicname()
    print(ch_nicname)
    logging.info("Change interface name command output is: [ %s ] and restart requirements is %s", ch_nicname.get("cmdout"), ch_nicname.get("netrestart"))
    if ch_nicname.get("netrestart"): netrestart = True

    # Restart Networking Service
    if netrestart:
        if nic.ostype == "redhat" or nic.ostype == "suse":
            print "service network restart"
            os.system('sudo service network restart')
        else:
            print 'Windows restart required'
            os.system('shutdown /r /t 1 /f /c "restart due to network configuration change"')

    # Update the server object hardware inventory in HPSA
    logging.info("Update the server object in HPSA")
    if nic.ostype == "windows":
        call(r"C:\Program Files\Opsware\agent\pylibs\cog\bs_hardware.bat")
    else:
        call(r"/opt/opsware/agent/pylibs/cog/bs_hardware")

    logging.info("Successfully completed IP configuration")

if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        if str(e) != '1' and str(e) != '2':   # Only complain if this is not a help exit
            print "I'm getting a sys.exit error '%s' from main" % str(e)
            traceback.print_exc()
            os._exit(1)

# C:\Program Files\Opsware\agent\lcpython15\
# /opt/opsware/agent/bin/
# python c:\temp\ipa.py --nicname nsb-bur-001  --nicip 192.168.0.253 --nicgw 192.168.0.254 --dnsips 4.4.4.2 8.8.8.8 --regdns --dnssuffixes alabala.md --niclabel koko
# python /root/ipa.py --nicname eth1 --routenet 149.123.21.0 --routemask 255.255.255.252  --routegw 192.168.0.253