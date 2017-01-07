#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import socket
import os
import subprocess

openvpn_cfg = "/etc/openvpn/bitcomm.conf"
openvpn_bin = "/usr/sbin/openvpn"
openvpn_pid = "/var/log/openvpn.pid"
hosts_file = "/etc/hosts"
ip_cmd = "/sbin/ip"


class AutoOpenVPN:

    def __init__(self):
        self.hosts = {}

    def get_openvpn_server(self, cfg_file):
        with open(cfg_file, "rt") as f:
            for line in f:
                l  = line.strip()
                if "#" == l[0:1]: #skip comment
                    continue
                else:
                    cfgs = l.split()
                    if cfgs[0] != "remote":
                        continue
                    else:
                        return cfgs[1]
        return ""

    def get_default_gw(self):
        cmd = [ip_cmd, "ro"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        route_lines = proc.stdout.readlines()
        for line in route_lines:
            route_words = line.split()
            if route_words[0] == b"default":
                return route_words[2]
        return None

    def connect_openvpn(self):
        openvpn_server = self.get_openvpn_server(openvpn_cfg)
        openvpn_server_ip = socket.gethostbyname(openvpn_server)
        gw = self.get_default_gw()
        cmd = "%s ro delete %s/32" % (ip_cmd, openvpn_server_ip)
        os.system(cmd)
        cmd = "%s ro add %s/32 via %s" % (ip_cmd, openvpn_server_ip, gw)
        os.system(cmd)

        cmd = "%s --config %s --writepid %s" % (openvpn_bin, openvpn_cfg, openvpn_pid)
        os.system(cmd)

    def loop(self):
        """
        1. resolve openvpn server
        2. add ip=>openvpn server to /etc/hosts
        3. add indepedence route to openvpn server
        4. connect openvpn server

        """
        openvpn_server = self.get_openvpn_server("/etc/openvpn/")
        pass

    def read_hosts(self):
        self.hosts = {}
        with  open(hosts_file, "rt") as f:
            for line in f:
                l = line.strip()
                if l == "" or l[0] == "#":
                    continue
                l = l.split()
                self.hosts[l[0]] = l[1]
        return self.hosts

    def write_hosts(self):
        if self.hosts == {}:
            return

        with open(hosts_file, "wt") as f:
            for k,v in self.hosts:
                f.write("%s  %s" % (k, v))








