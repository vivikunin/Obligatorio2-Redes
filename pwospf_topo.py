#!/usr/bin/python

"""
Start up the topology for PWOSPF
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class CS144Topo( Topo ):
    "CS 144 Lab 3 Topology"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        server1 = self.addHost( 'server1' )
        server2 = self.addHost( 'server2' )
        vhost1 = self.addSwitch( 'vhost1' )
        vhost2 = self.addSwitch( 'vhost2' )
        vhost3 = self.addSwitch( 'vhost3' )
        vhost4 = self.addSwitch( 'vhost4' )
        vhost5 = self.addSwitch( 'vhost5' )
        client = self.addHost('client')

        self.addLink(client, vhost1)
        self.addLink(vhost2, vhost1)
        self.addLink(vhost3, vhost1)        
        self.addLink(vhost2, vhost4)
        self.addLink(vhost3, vhost5)
        self.addLink(vhost3, vhost2)
        self.addLink(server1, vhost4)
        self.addLink(server2, vhost5)
        self.addLink(vhost4, vhost5)


class CS144Controller( Controller ):
    "Controller for CS144 Multiple IP Bridge"

    def __init__( self, name, inNamespace=False, command='controller',
                 cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                 port=6633, **params ):
        """command: controller command name
           cargs: controller command arguments
           cdir: director to cd to before running controller
           ip: IP address for controller
           port: port for controller to listen at
           params: other params passed to Node.__init__()"""
        Controller.__init__( self, name, ip=ip, port=port, **params)

    def start( self ):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""
        pathCheck( self.command )
        cout = '/tmp/' + self.name + '.log'
        if self.cdir is not None:
            self.cmd( 'cd ' + self.cdir )
        self.cmd( self.command, self.cargs % self.port, '>&', cout, '&' )

    def stop( self ):
        "Stop controller."
        self.cmd( 'kill %' + self.command )
        self.terminate()


def startsshd( host ):
    "Start sshd on host"
    stopsshd()
    info( '*** Starting sshd\n' )
    name, intf, ip = host.name, host.defaultIntf(), host.IP()
    banner = '/tmp/%s.banner' % name
    host.cmd( 'echo "Welcome to %s at %s" >  %s' % ( name, ip, banner ) )
    host.cmd( '/usr/sbin/sshd -o "Banner %s"' % banner, '-o "UseDNS no"' )
    info( '***', host.name, 'is running sshd on', intf, 'at', ip, '\n' )


def stopsshd():
    "Stop *all* sshd processes with a custom banner"
    info( '*** Shutting down stale sshd/Banner processes ',
          quietRun( "pkill -9 -f Banner" ), '\n' )


def startRPC( host ):
    "Start RPC test server on hosts"
    info( '*** Starting JSONRPC Server on host', host, '\n' )
    host.cmd( 'cd ./dist/; nohup python3.8 ./test-server.py &' )


def stopRPC():
    "Stop RPC servers"
    info( '*** Shutting down stale RPCServers', 
          quietRun( "pkill -9 -f test-server" ), '\n' )    
    
def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['vhost4-eth2']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['vhost5-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['vhost1-eth1']
    print host.name, routerip
    #host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    #ips = IP_SETTING[host.name].split(".") 
    #host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def get_ip_setting():
    if (not os.path.isfile(IPCONFIG_FILE)):
        return -1
    f = open(IPCONFIG_FILE, 'r')
    for line in f:
        if( len(line.split()) == 0):
          break
        name, ip = line.split()
        print name, ip
        IP_SETTING[name] = ip
    return 0

def cs144net():
    stopRPC()
    "Create a simple network for cs144"
    r = get_ip_setting()
    if r == -1:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    else:
        info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)

    topo = CS144Topo()
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController)
    net.start()
    server1, server2, client = net.get( 'server1', 'server2', 'client')
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/24' % IP_SETTING['server1'])
    s2intf = server2.defaultIntf()
    s2intf.setIP('%s/24' % IP_SETTING['server2'])
    clintf = client.defaultIntf()
    clintf.setIP('%s/24' % IP_SETTING['client'])


    #cmd = ['ifconfig', "eth1"]
    #process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    #hwaddr = Popen(["grep", "HWaddr"], stdin=process.stdout, stdout=PIPE)
    #eth1_hw = hwaddr.communicate()[0]
    #info( '*** setting mac address of sw0-eth3 the same as eth1 (%s)\n' % eth1_hw.split()[4])
    #router.intf('sw0-eth3').setMAC(eth1_hw.split()[4])
    
   
    #for host in server1, server2, client:
    for host in server1, server2, client:
        set_default_route(host)
    #startRPC( server1 )
    #startRPC( server2 )
    CLI( net )
    stopRPC()
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    cs144net()
