# "C:\Program Files\Opsware\agent\lcpython15\python" c:\temp\winNetConfig.py --nicname nsb-bur-001  --nicip 192.168.0.253 --nicgw 192.168.0.254 --dnsips 4.4.4.2 8.8.8.8 --regdns --dnssuffixes alabala.md --niclabel koko

import sys
import os
import re
import time
import logging
import inspect
import traceback
import platform
import argparse
import pprint
from subprocess import Popen, PIPE
from subprocess import call

cog_dir = 'C:\Program Files\Opsware\agent\pylibs\cog'
sys.path.append(cog_dir)


parser = argparse.ArgumentParser(description = 'Set the Network IP Address')
parser.add_argument('--nicname', default = 'eth0', help='network adapter name')
parser.add_argument('--nicip', default = '192.168.0.1', help='IP address')
parser.add_argument('--nicmask', default = '255.255.255.0', help='IP mask')
parser.add_argument('--nicgw', nargs='?', help='IP gateway')
parser.add_argument('--niclabel', nargs='?', help='configure interface label, optional')
parser.add_argument('--dnsips', nargs='*', help='list of DNS servers for a given interface separated by space, optional')
parser.add_argument('--dnssuffixes', nargs='*', help='configure DNS Domain Search Suffixes, optional')
parser.add_argument('--regdns', action='store_true', help='register NIC in DNS, optional')
parser.add_argument('--routenet', nargs='?', help='static route network ip')
parser.add_argument('--routemask', nargs='?',help='static route network mask')
parser.add_argument('--routegw', nargs='?', help='static route gateway')
parser.add_argument('--defroute', nargs='?', help='default route')
parser.add_argument('--loglevel', default = 'INFO', help='FATAL, ERROR, WARNING, INFO, DEBUG')
parser.add_argument('--logfile', default = 'ipa.log', help='Logfile to store messages (Default: ipa.log)')
parser.add_argument('--quiet', action='store_true', help='Do not print logging to stdout')


def win_cmd(cmdLine):
    print cmdLine
    proc = Popen(cmdLine, universal_newlines=True, stderr=PIPE, stdout=PIPE)
    (stdout, stderr) = proc.communicate()
    if proc.returncode != 0:
        print("The command failed with code: %d error: %s" % (proc.returncode, stderr))
        raise RuntimeError(stderr + stdout)
    else :
        #print(stdout)
        print('CMD EXIT')
    return stdout
	
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
    logging.info("Automate IP Address Management")
    logging.info("\r\nArguments:\r\n")
#    logging.info(pprint.pprint(vars(args)))	
    logging.info("Arguments: " + str(vars(args)))	
    # OS version
    is_windows=(platform.system().lower().find("win") > -1)
    is_redhat=(platform.linux_distribution()[0].lower().find("red hat") > -1)
    is_suse=(platform.linux_distribution()[0].lower().find("suse") > -1)
	
    # Validate inputs
    if is_windows:
        try:
            cmdLine = 'netsh int ip set address "' + args.nicname + '" static ' + args.nicip + ' ' + args.nicmask + (' ' + args.nicgw if args.nicgw else '')
            win_cmd(cmdLine)
            time.sleep(1)
            win_cmd(cmdLine)
            cmdLine = 'netsh int ip show addresses "' + args.nicname + '"' 
            win_cmd(cmdLine)
            logging.info("DNS configuration")
            logging.info("==================")
            if args.dnsips:
                logging.info("DNS list: %s" % args.dnsips)
                if args.regdns is True:
                    #print "args.regdns: " + str(args.regdns)			
                    logging.info("register NIC in DNS")
                    regdns = "primary"
                else:
                    logging.info("will not register NIC in DNS")
                    regdns = "none"
                logging.info(" First DNS configuration")
                cmdLine = 'netsh int ip set dns "' + args.nicname + '" static ' + args.dnsips[0] + ' ' + regdns
                # print(cmdLine)
                win_cmd(cmdLine)
                dnscount = int(args.dnsips.__len__())
                #print(dnscount)
                for i in range(1, dnscount):
                    #print "Adding %d) server %s to the DNS." % i, args.dnsips[i]
                    if args.dnsips[i]:
                        #netsh int ip add dns "$Network_Adapter" $DNS_Servers[$i] index=($i+1)
                        cmdLine = 'netsh int ip add dns "' + args.nicname + '" ' + args.dnsips[i] + ' index=' + str(i+1)
                        print(cmdLine)
                        win_cmd(cmdLine)
            else:
                logging.info("DNS list is empty")
			# reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "SearchList" /d "" /f
            if args.dnssuffixes:
                logging.info("DNS suffixes: %s" % args.dnssuffixes)
                cmdLine = 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "SearchList"'
                # print(cmdLine)
                stdout = win_cmd(cmdLine)
                # print(stdout)
                dnssuff = re.search(r"SearchList\s+REG_SZ\s+([\w\.\,\ ]+)", stdout)
                curdnssuff = str(dnssuff.group(1)).strip()
                #print('curdnssuff: ' + curdnssuff)
                if curdnssuff:
                    #print 'Successful match'
                    curdnssuff = dnssuff.group(1)
                    dnssuffixes = ",".join(str(bit) for bit in args.dnssuffixes) + (', ' + curdnssuff if curdnssuff else '')
                    #print(dnssuffixes)
                else:
                    #print 'Unsuccessful match'
                    dnssuffixes = ",".join(str(bit) for bit in args.dnssuffixes)
                cmdLine = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "SearchList" /d "' + dnssuffixes + '" /f'
                #print(cmdLine)
                stdout = win_cmd(cmdLine)
                #print(stdout)
            else:
                logging.info("DNS suffixes list is empty")

            if args.routenet and args.routemask and args.routegw:
                logging.info("The NIC label is changed to: %s" % args.niclabel)
                cmdLine = 'route add ' + args.routenet + ' mask ' + args.routemask + ' ' + args.routegw + ' -p'
                #print(cmdLine)
                win_cmd(cmdLine)
            else:
                logging.info("Skip  static route configuration. Missing network, mask or gateway argument.")

            if args.defroute: 
                cmdLine = 'route add 0.0.0.0 mask 0.0.0.0 ' + args.defroute + ' /p'
                win_cmd(cmdLine)
                logging.info("The default route is changed to: %s" % args.defroute)
                cmdLine = 'route print 0.0.0.0'
                stdout = win_cmd(cmdLine)
                print(stdout)
                for defrt in re.finditer(r"(?:0\.){3}0\s*(?:0\.){3}0\s+(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", stdout):
                    print str(defrt.group(1)).strip()
                    if str(args.defroute).strip() == str(defrt.group(1)).strip():
                        logging.info("Keep new default route.")
                    else:
                        cmdLine = 'route delete 0.0.0.0 mask 0.0.0.0 ' + str(defrt.group(1)).strip()
                        win_cmd(cmdLine)
            else:
                logging.info("no change in the default route")
				
            if args.niclabel:
                logging.info("The NIC label is changed to: %s" % args.niclabel)
                cmdLine = 'netsh int set interface name="' + args.nicname + '"  newname="' + args.niclabel + '"'
                #print(cmdLine)
                win_cmd(cmdLine)
            else:
                logging.info("NIC will retain default name")
            logging.info("Update the server object in HPSA")
            call(r"C:\Program Files\Opsware\agent\pylibs\cog\bs_hardware.bat")

        except:
            print "Something Didn't Work"
            raise RuntimeError('The command failed')
    elif is_redhat:
        try:
            print "This is Red Hat"		
        except:
            print "Something Didn't Work"
            raise RuntimeError('The command failed')
    elif is_suse:
        try:
            print "This is SUSE"		
        except:
            print "Something Didn't Work"
            raise RuntimeError('The command failed')
    else:
        print >> sys.stderr, '*** The OS "%s" is not supported ***' % platform.linux_distribution()[0]


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        if str(e) != '1' and str(e) != '2':   # Only complain if this is not a help exit
            print "I'm getting a sys.exit error '%s' from main" % str(e)
            traceback.print_exc()
            os._exit(1)