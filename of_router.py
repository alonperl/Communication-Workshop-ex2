"""
Authors:
David Saper - 302598032 dav_sap
Alon Perelmuter - 20063088 alonperl
"""


from pox.core import core
import pox.openflow.libopenflow_01 as of
from utils import *
from pox.lib.packet.lldp import lldp, chassis_id, port_id, ttl, end_tlv
from pox.lib.packet.ethernet import ethernet
import pox.openflow.nicira as nx
import time
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import echo, unreach, icmp
import struct
from priority_dict import priority_dict


# our own imports
import itertools
import threading

CONFIG_FILENAME = '/home/mininet/config'
log = core.getLogger()


class RoutingTable(object):
    def __init__(self):
        self.table = {}

    def add(self, address, mask, destination):
        """
        Adds an address with a specified subnet mask and destination port to the routing table. Parameters:
        address: IP address (String of four integers in [0,255], such as "10.0.0.1")
        mask: Subnet mask (String of four integers in [0,255], such as "255.255.255.0")
        destination: Either a port number, or some other value, as you wish to have in the table.
        The method does not return any value. If an entry exists for the same masked address, then the old entry is replaced by the new entry.
        """
        tup_mask = self.ipv4_str_to_int_tuple(mask)
        address_subnet = self.ipv4_get_subnet(self.ipv4_str_to_int_tuple(address), tup_mask)
        self.table[(address_subnet, tup_mask)] = destination

    @staticmethod
    def ipv4_str_to_int_tuple(ip_str):
        return tuple(map(int, ip_str.split(".")))

    @staticmethod
    def ipv4_get_subnet(ipv4_tup, mask_tup):
        return tuple(x & y for x, y in itertools.izip(ipv4_tup, mask_tup))

    @staticmethod
    def ipv4_tup_to_str(addr):
        return str(addr).replace("(", "").replace(")", "").replace(", ", ".")

    def lookup(self, address):
        """
        Looks up a given address in the table. Parameter address is a string of an IP address
        (as in add). If there is a corresponding entry in the table (with regard to address and subnet mask),
        then the destination of that entry is returned. Otherwise, the method returns None.
        """
        address_tup = self.ipv4_str_to_int_tuple(address)
        for key, dest in self.table.iteritems():
            if self.ipv4_get_subnet(address_tup, key[1]) == key[0]:
                return dest

    def __str__(self):
        table_str = ''
        for key, dest in self.table.iteritems():
            table_str += '\nsubnet: ' + self.ipv4_tup_to_str(key[0] + ", mask: " +
                                                            self.ipv4_tup_to_str(key[1]) + ", destination: " + dest)


class Network(object):
    __metaclass__ = SingletonType

    class Router(object):
        def __init__(self, dpid):
            self.dpid = dpid
            self.ports = {}  # id:ports(object)
            self.table = RoutingTable()

    class Port(object):
        def __init__(self):
            self.__ip = None
            self.__mask = None
            self.__mac = None
            self.__router = None

        @property
        def router(self):
            return self.__router

        @router.setter
        def router(self, value):
            self.__router = value

        @property
        def ip(self):
            return self.__ip

        @ip.setter
        def ip(self, value):
            self.__ip = value

        @property
        def mask(self):
            return self.__mask

        @mask.setter
        def mask(self, value):
            self.__mask = value

        @property
        def mac(self):
            return self.__mac

        @mac.setter
        def mac(self, value):
            self.__mac = value

    def __init__(self):
        self.routers = {}  # id:Router(object)
        self.edges = {}  # ((R,Port1),(R,Port2)) : cost
        self.lock = threading.Lock()
        self.parse_config()

    ROUTER = 'router'
    NUM_OF_ATTRIB = 3
    LINK = 'link'
    PORTS = 'ports'
    END_OF_FILE = ''
    RELOAD = 'reload'
    FILENAME = 'config.txt'

    def parse_config(self):
        self.lock.acquire()
        self.routers.clear()
        self.edges.clear()
        self.lock.release()
        f = open(self.FILENAME, 'r')
        line = f.readline()
        while line != self.END_OF_FILE:
            split_line = line.split()
            if line.startswith(self.ROUTER):
                r = self.Router(int(split_line[1]))
                line = f.readline()
                if line.startswith(self.PORTS):
                    split_line = line.split()

                    for i in range(int(split_line[1])):
                        port_dpid = f.readline().split()
                        r.ports[int(port_dpid[1])] = self.Port()

                        for attrib in range(self.NUM_OF_ATTRIB):
                            port_attrib = f.readline().split()
                            setattr(r.ports[int(port_dpid[1])], port_attrib[0], port_attrib[1])
                        setattr(r.ports[int(port_dpid[1])], self.ROUTER, r)
                    self.lock.acquire()
                    self.routers[r.dpid] = r
                    self.lock.release()
                line = f.readline()
            elif line.startswith(self.LINK):
                split_line = f.readline().split()
                edge_one = split_line[1].split(',')
                self.lock.acquire()
                port_one = self.routers[int(edge_one[0])].ports[int(edge_one[1])]
                split_line = f.readline().split()
                edge_two = split_line[1].split(',')
                port_two = self.routers[int(edge_two[0])].ports[int(edge_two[1])]
                split_line = f.readline().split()
                self.edges[(port_one, port_two)] = int(split_line[1])
                self.lock.release()
                line = f.readline()
            elif line.startswith('\n'):
                line = f.readline()
            elif line.startswith(self.RELOAD):
                split_line = line.split()
                threading.Timer(int(split_line[1]), self.parse_config).start()
                line = f.readline()
            elif line.startswith(self.END_OF_FILE):
                break

    def get_routing_table(self, router_id):
        #add all the local subnets to the routing table
        r = self.get_router_by_id(router_id)
        for port_id,port in r.ports.iteritems():
            r.table.add(port.ip,port.mask,port)

        shortest_paths = self.compute_dijkstra(router_id)
        for r_id,rout in self.routers.iteritems():
            for port_id,port in rout.iteritems():
                if not r.table.lookup(port.ip):
                    next_rout = self.get_router_by_id(shortest_paths[r_id])
                    self.find_port(rout, next_rout)

                    r.table.add(port.ip,port.mask, )



    def find_port(self, router_src, router_dest):
        for edge in self.edges:

    def get_router_by_id(self, dpid):
        for r_id,r in self.routers.iteritems():
            if r_id == dpid:
                return r
    def compute_dijkstra(self, src_router_id):
        src_router = self.get_router_by_id(src_router_id)
        q = priority_dict()
        prev = {}
        for r_id, r in self.routers.iteritems():
            q[r] = float("inf")
        q[src_router] = 0
        while q:
            dist = q[q.smallest()]
            u = q.pop_smallest()

            # v[0] = Router-neighbor, v[1] = cost
            for v in self.get_neighbors(u):
                if v[0] in q:
                    alt = dist + v[1]
                    if alt < q[v[0]]:
                        q[v[0]] = alt
                        prev[v[0]] = u
        next_hop = self.get_next_hop(src_router, prev)
        # for key, val in next_hop.iteritems():
        #     print key.dpid, val.dpid
        return next_hop

    def get_next_hop(self, src_router, prev_list):
        next_hop = {}
        # for r_id, r in self.routers.iteritems():
        #     if prev_list[r] == src_router:

        for r, r_prev in prev_list.iteritems():
            tmp = r_prev
            if tmp is src_router:
                next_hop[r.dpid] = r.dpid
            else:
                while tmp is not src_router:
                    if prev_list[tmp] is src_router:
                        next_hop[r.dpid] = tmp.dpid
                    tmp = prev_list[tmp]
        return next_hop
    def compute_ospf(self):
        ospf = {}
        for r_id in self.routers:
            ospf[r_id] = self.compute_dijkstra(r_id)
        return ospf

    def get_neighbors(self, src_router):
        neighbors = []
        for p_id, port in src_router.ports.iteritems():
            neighbor = self.get_router(port)
            if neighbor:
                neighbors.append(neighbor)
        return neighbors

    def get_router(self, port):
        for edge in self.edges:
            if port == edge[0]:
                return edge[1].router, self.edges[edge]
            elif port == edge[1]:
                return edge[0].router, self.edges[edge]
class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        self.forward_table = {}
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Ignore IPv6 discovery messages
        if "33:33:00:00:00:" in str(packet.dst):
            return

        packet_in = event.ofp # packet_in is the OpenFlow packet sent by the switch

        self.act_like_switch(packet, packet_in)

    def send_packet (self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """
        # We tell the switch to take the packet with id buffer_if from in_port
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data

        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def send_flow_mod(self, packet, packet_in, out_port):
        fm = of.ofp_flow_mod()
        fm.match.in_port = packet_in.in_port
        fm.match.dl_dst = packet.dst
        fm.match.dl_src = packet.src
        # it is not mandatory to set fm.data or fm.buffer_id
        if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
            # Valid buffer ID was sent from switch, we do not need to encapsulate raw data in response
            fm.buffer_id = packet_in.buffer_id
        else:
            if packet_in.data is not None:
                # No valid buffer ID was sent but raw data exists, send raw data with flow_mod
                fm.data = packet_in.data
            else:
                return
        action = of.ofp_action_output(port=out_port)
        fm.actions.append(action)

        # Send message to switch
        self.connection.send(fm)


    def act_like_switch(self, packet, packet_in):

        if packet.src in self.forward_table and packet_in.in_port != self.forward_table[packet.src]:
            self.remove_flow(packet.src)
        self.forward_table[packet.src] = packet_in.in_port


        if packet.dst in self.forward_table:
            log.debug('Found dest in table. Adding flow rule for: packet: dest = {}; src = {}; in_port = {}'.format(packet.dst, packet.src, packet_in.in_port))
            self.send_flow_mod(packet, packet_in, self.forward_table[packet.dst])
        else:
            ####FLOODING
            log.debug('Flooding packet: dest = {}; src = {}; in_port = {}'.format(packet.dst, packet.src, packet_in.in_port))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

    def remove_flow(self, source):
        log.debug('Remove flow rule in SW: {}; dl_dest = {}'.format(self.connection.dpid, source))
        fm = of.ofp_flow_mod()
        fm.command = of.OFPFC_DELETE
        fm.match.dl_dst = source # change this if necessary
        self.connection.send(fm) # send flow-mod message



def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)

