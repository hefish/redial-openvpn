#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import socket
import os
import subprocess
import atexit
import time
import sys
from signal import SIGTERM
from pprint import pprint

openvpn_cfg = "/etc/openvpn/bitcomm.conf"
openvpn_bin = "/usr/sbin/openvpn"
openvpn_pid = "/var/log/openvpn.pid"
hosts_file = "/etc/hosts"
ip_cmd = "/sbin/ip"


class AutoOpenVPN:
    def __init__(self):
        self.hosts = {}

    @staticmethod
    def get_openvpn_server(cfg_file):
        with open(cfg_file, "rt") as f:
            for line in f:
                l = line.strip()
                if "#" == l[0:1]:
                    continue
                else:
                    cfgs = l.split()
                    if cfgs[0] != "remote":
                        continue
                    else:
                        return cfgs[1]
        return ""

    @staticmethod
    def get_default_gw():
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
        print("getting default gateway... "),
        gw = self.get_default_gw()
        print(gw)

        print("add independent route to vpn server..."),
        cmd = "%s ro delete %s/32" % (ip_cmd, openvpn_server_ip)
        os.system(cmd)
        cmd = "%s ro add %s/32 via %s" % (ip_cmd, openvpn_server_ip, gw)
        os.system(cmd)
        print("done")

        print("getting hosts file... "),
        hosts = self.read_hosts()
        for k, v in hosts.items():
            print("%s => %s" % (k, v))
        print("add vpn server to hosts ..."),
        hosts[openvpn_server_ip] = openvpn_server
        for k, v in hosts.items():
            print("%s => %s" % (k, v))

        print("updating hosts file ... "),
        self.hosts = hosts
        self.write_hosts()
        print("done")

        print("starting openvpn client...")
        cmd = "%s --config %s --writepid %s" % (openvpn_bin, openvpn_cfg, openvpn_pid)
        os.system(cmd)

    def read_hosts(self):
        self.hosts = {}
        with open(hosts_file, "rt") as f:
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
            for k, v in self.hosts.items():
                f.write("%s  %s" % (k, v))

    def loop(self):
        """
        1. resolve openvpn server
        2. add ip=>openvpn server to /etc/hosts
        3. add independent route to openvpn server
        4. connect openvpn server
        """
        while True:
            self.connect_openvpn()


class Daemon:
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d(%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, "r")
        so = file(self.stdout, "a+")
        se = file(self.stderr, "a+", 0)

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        atexit.register(self.delete_pid)
        pid = str(os.getpid())
        file(self.pidfile, "w+").write("%s\n" % pid)

        return

    def delete_pid(self):
        os.remove(self.pidfile)

    def start(self):
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exist. Daemon may already running. \n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        self.daemonize()
        self.run()

    def stop(self):
        try:
            pf = file(self.pidfile, "r")
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon may not running. "
            sys.stderr.write(message % self.pidfile)
            return

        try:
            while True:
                os.kill(pid, SIGTERM)
                time.sleep(0.5)
        except OSError, e:
            err = str(e)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print err
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

    def run(self):
        pass


class OpenVPNDaemon(Daemon):
    def run(self):
        o = AutoOpenVPN()
        o.loop()


if __name__ == "__main__":
    daemon = OpenVPNDaemon("/var/run/autovpn.pid", "/dev/null", "/var/log/autodial.out", "/var/log/autodial.err")
    if len(sys.argv) == 2:
        if "start" == sys.argv[1]:
            daemon.start()
        elif "stop" == sys.argv[1]:
            daemon.stop()
        elif "restart" == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command: %s " % sys.argv[1]
            sys.exit(2)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
