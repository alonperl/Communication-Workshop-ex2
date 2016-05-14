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
tutorial_list = {}

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
            table_str += '\nsubnet: ' + self.ipv4_tup_to_str(key[0]) + ", mask: " +\
                                                            self.ipv4_tup_to_str(key[1]) + ", destination: " + str(dest.id)
        return  table_str
class Network(object):
    __metaclass__ = SingletonType

    class Router(object):
        def __init__(self, dpid):
            self.dpid = dpid
            self.ports = {}  # id:ports(object)
            self.tutorial = None


    class Port(object):
        def __init__(self):
            self.__ip = None
            self.__mask = None
            self.__mac = None
            self.__router = None
            self.__id = None

        @property
        def router(self):
            return self.__router

        @router.setter
        def router(self, value):
            self.__router = value

        @property
        def id(self):
            return self.__id

        @id.setter
        def id(self, value):
            self.__id = value

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
        log.debug("!!!!!!!!!!!!!!!!! NETWORK INIT")
        self.routers = {}  # id:Router(object)
        self.edges = {}  # ((Port1 obj),(Port2 obj)) : cost
        self.lock = threading.Lock()
        self.parsed = False
        self.parse_config()

    ROUTER = 'router'
    NUM_OF_ATTRIB = 3
    LINK = 'link'
    PORTS = 'ports'
    END_OF_FILE = ''
    RELOAD = 'reload'
    FILENAME = CONFIG_FILENAME

    def parse_config(self):
        self.lock.acquire()
        self.routers.clear()
        self.edges.clear()
        f = open(self.FILENAME, 'r')
        line = f.readline()
        while line != self.END_OF_FILE:
            split_line = line.split()
            if line.startswith(self.ROUTER):
                r = self.Router(int(split_line[1]))
                self.routers[r.dpid] = r
                if self.parsed and r.dpid in tutorial_list:
                    self.set_tutorial(r.dpid, tutorial_list[r.dpid])
                line = f.readline()
                if line.startswith(self.PORTS):
                    split_line = line.split()

                    for i in range(int(split_line[1])):
                        port_dpid = f.readline().split()
                        r.ports[int(port_dpid[1])] = self.Port()
                        setattr(r.ports[int(port_dpid[1])], 'id', int(port_dpid[1]))
                        for attrib in range(self.NUM_OF_ATTRIB):
                            port_attrib = f.readline().split()
                            setattr(r.ports[int(port_dpid[1])], port_attrib[0], port_attrib[1].lower())
                        setattr(r.ports[int(port_dpid[1])], self.ROUTER, r)

                line = f.readline()
            elif line.startswith(self.LINK):
                split_line = f.readline().split()
                edge_one = split_line[1].split(',')

                port_one = self.routers[int(edge_one[0])].ports[int(edge_one[1])]
                split_line = f.readline().split()
                edge_two = split_line[1].split(',')
                port_two = self.routers[int(edge_two[0])].ports[int(edge_two[1])]
                split_line = f.readline().split()
                self.edges[(port_one, port_two)] = int(split_line[1])

                line = f.readline()
            elif line.startswith('\n'):
                line = f.readline()
            elif line.startswith(self.RELOAD):
                split_line = line.split()
                if not self.parsed:
                    Timer(interval=int(split_line[1]), function=self.parse_config, args=[], recurring=True)
                line = f.readline()
            elif line.startswith(self.END_OF_FILE):
                break
        if self.parsed:
            self.update_flow_rules()
        self.parsed = True
        self.lock.release()

    def update_flow_rules(self):
        """

            """
        log.debug("In update flow rules!")
        for r_id, r in self.routers.iteritems():
            r_table = self.get_routing_table(r_id)
            if r.tutorial:
                for fr in r.tutorial.flow_rules:
                    
                    # check if there is port conflict for old flow mod vs. new routing table
                    lookup = r_table.lookup(fr[1])
                    # if lookup:
                    #     log.debug("r_id : {} r_table: {}\n lookup: {}".format(r_id, str(r_table), lookup.id))
                    if lookup and lookup.id == fr[2].id:
                        continue
                    else:
                        fm = of.ofp_flow_mod()
                        fm.command = of.OFPFC_DELETE
                        fm.match.in_port = int(fr[0])
                        fm.match.dl_type = ethernet.IP_TYPE
                        # fm.match.dl_dst = EthAddr(fr[3])
                        fm.match.nw_dst = IPAddr(fr[1])
                        log.debug("Removing Flow Rule for router {}, port {}, dstip {}".format(r_id, fr[2].id, fr[1]))
                        r.tutorial.flow_rules.remove(fr)
                        r.tutorial.connection.send(fm)
            else:
                log.debug("rid: {} Tutorial not exist".format(r_id))

    def get_routing_table(self, router_id):
        # add all the local subnets to the routing table
        r = self.get_router_by_id(router_id)
        r_table = RoutingTable()
        for port_id, port in r.ports.iteritems():
            r_table.add(port.ip,port.mask,port)

        shortest_paths = self.compute_dijkstra(router_id)
        for r_id,rout in self.routers.iteritems():
            if rout is not r:
                for port_id, port in rout.ports.iteritems():
                    if not r_table.lookup(port.ip):
                        next_rout = self.get_router_by_id(shortest_paths[r_id])
                        r_table.add(port.ip, port.mask, self.find_port(r, next_rout))
        return r_table

    def find_port(self, router_src, router_dest):
        ports = priority_dict()

        for edge in self.edges:

            if router_src == edge[0].router and router_dest == edge[1].router:
                ports[edge[0]] = self.edges[edge]
            if router_src == edge[1].router and router_dest == edge[0].router:
                ports[edge[1]] = self.edges[edge]

        return ports.pop_smallest()

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
        ret = None
        for edge in self.edges:
            if port == edge[0]:
                if ret:
                    if ret[1] > self.edges[edge]:
                        ret = edge[1].router, self.edges[edge]
                else:
                    ret = edge[1].router, self.edges[edge]
            elif port == edge[1]:
                if ret:
                    if ret[1] > self.edges[edge]:
                        ret = edge[0].router, self.edges[edge]
                else:
                    ret =  edge[0].router, self.edges[edge]
        return ret

    def set_tutorial(self, dpid, t):
        self.routers[dpid].tutorial = t


class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        self.forward_table = {}
        self.connection = connection
        self.arp_cache = {} # ip : (mac_address, timestamp)
        self.waiting_arp_requests = {} # ip : (packet, packet-in, timestamp)
        # This binds our PacketIn event listener
        connection.addListeners(self)
        self.lock = threading.Lock()
        self.network = Network()
        self.flow_rules = []  # [(packet_in.in_port, destIP, dest_port, destMac)]
        self.arp_timer = Timer(interval=3, function=self.clean_arp_cache, args=[], recurring=True)

    def clean_arp_cache(self):
        self.lock.acquire()
        for ip, arp_req in self.waiting_arp_requests.iteritems():
            if arp_req[2] - time.time() > 3:
                # handle_ip to reply for the packet that host unreachable
                self.handle_ip(self.waiting_arp_requests[ip][0], self.waiting_arp_requests[ip][1])
                # TODO: to check if del is not deleting the tuple
                del self.waiting_arp_requests[ip]
                self.arp_cache[ip] = (None, time.time())
        for ip, arp_data in self.arp_cache.iteritems():
            if arp_data[0] is None and arp_data[1] - time.time() > 5 or\
               arp_data[1] - time.time() > 3600:
                del self.arp_cache[ip]
        self.lock.release()

    def handle_ip(self, packet, packet_in):
        self.network.lock.acquire()
        r_table = self.network.get_routing_table(self.connection.dpid)
        dest_ip = str(packet.payload.dstip)
        dest_port = r_table.lookup(dest_ip) # Port object
        in_port_data = self.network.routers[self.connection.dpid].ports[packet_in.in_port]
        log.debug("handle_ip called in router_id: {} srcip: {} dstip: {} ttl: {}".format(self.connection.dpid,str(packet.payload.srcip),dest_ip, packet.payload.ttl))

        if dest_port and packet.payload.ttl > 1:

            # 7.C - If the destination port is not None, and it is not the same port the packet came on
            if dest_port.id != packet_in.in_port:
                mask_tup = r_table.ipv4_str_to_int_tuple(dest_port.mask)
                dest_port_subnet = r_table.ipv4_get_subnet(r_table.ipv4_str_to_int_tuple(dest_port.ip), mask_tup)
                dest_ip_subnet_dest_mask = r_table.ipv4_get_subnet(r_table.ipv4_str_to_int_tuple(dest_ip), mask_tup)
                # 7.C.a - if the destination IP is in the subnet of the destination port
                if dest_ip_subnet_dest_mask == dest_port_subnet:

                    if dest_ip in self.arp_cache:
                        # I - If the destination IP address is in arp_cache and it is mapped to a valid MAC address.
                        if self.arp_cache[dest_ip][0]:
                            dest_mac = self.arp_cache[dest_ip][0]
                            log.debug("handle_ip router_id {}; part 7.C.a.I".format(self.connection.dpid))
                            self.send_router_flow(dest_ip, packet_in, dest_port, dest_mac, False)
                            self.network.lock.release()
                            return
                        # II - If the destination IP address is in arp_cache but it is mapped to None,
                        else:
                            log.debug("handle_ip router_id {}; part 7.C.a.II".format(self.connection.dpid))
                            self.send_icmp(3, 1, str(packet.payload.srcip), str(packet.payload.hwsrc), in_port_data, packet)
                            self.network.lock.release()
                            return
                    # III - If the destination IP is not in arp_cache at all
                    else:
                        log.debug("handle_ip router_id {}; part 7.C.a.III".format(self.connection.dpid))
                        log.debug("handle_ip router_id {}; Destination host ip {} -> MAC addr is unknown, ARP req sent"
                                  " to find it".format(self.connection.dpid, dest_ip))
                        self.waiting_arp_requests[dest_ip] = (packet, packet_in, time.time())
                        self.send_arp_request(dest_ip, dest_port)
                        self.network.lock.release()
                        return
                # 7.C.b - Create a flow_mod message to the router
                self.send_router_flow(dest_ip, packet_in, dest_port, None, False)
                self.network.lock.release()
                log.debug("handle_ip router_id {}; part 7.C.b".format(self.connection.dpid))
                return
            # 7.D - If the destination port is the same port the packet came on
            elif dest_port.id == packet_in.in_port:
                # 7.D.a - if the destination IP address is the IP address of the port the packet came on
                if dest_ip == in_port_data.ip:

                    if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                        # 7.D.a.I --> ICMP ECHO REQUEST
                        if packet.payload.payload.type == 8:
                            log.debug("handle_ip router_id {}; part 7.D.a.I".format(self.connection.dpid))
                            log.debug("handle_ip router_id {}; Got ICMP ECHO REQUEST from ip: ".format(
                                self.connection.dpid, str(packet.payload.srcip)))
                            self.send_icmp(0, 0, str(packet.payload.srcip), str(packet.src), in_port_data, packet)
                        # 7.D.a.II - another type of ICMP --> ignore
                        else:
                            self.network.lock.release()
                            log.debug("handle_ip router_id {}; part 7.D.a.II".format(self.connection.dpid))
                            log.debug("handle_ip router_id {}; NOT AN ICMP IP_PACKET".format(self.connection.dpid))
                            return
                    # 7.D.a.III - if not ICMP
                    else:
                        log.debug("handle_ip router_id {}; part 7.D.a.III".format(self.connection.dpid))
                        log.debug("handle_ip router_id {}; Destination port for IP packet is unreachable".format(
                            self.connection.dpid))
                        self.send_icmp(3, 3, str(packet.payload.srcip), str(packet.src), in_port_data, packet)
                        self.network.lock.release()
                        return
                # 7.D.b - If the destination IP address is not the IP address of the port the packet came on - drop
                else:
                    log.debug("handle_ip router_id {}; part 7.D.b".format(self.connection.dpid))
                    log.debug("handle_ip router_id {}; Destination host for IP : {} is unreachable".format(
                        self.connection.dpid, dest_ip))
                    self.send_router_flow(dest_ip, packet_in, None, None, True)
        # 7.E If TTL is less than 2, packet should be dropped and an ICMP TTL Expired (type=11, code=0)
        #  message should be sent to the source IP address.
        elif dest_port and packet.payload.ttl <= 1:
            log.debug("handle_ip router_id {}; part 7.E".format(self.connection.dpid))
            log.debug("handle_ip router_id {}; TTL exceeded".format(self.connection.dpid))
            self.send_icmp(11, 0, str(packet.payload.srcip), str(packet.src), in_port_data, packet)
            self.network.lock.release()
            return
        # 7.F If the destination port is None (unknown), the destination network is unreachable from this router.
        # Send an ICMP Destination Network Unreachable (type=3, code=0) message to the source IP address.
        elif not dest_port:
            log.debug("handle_ip router_id {}; part 7.F".format(self.connection.dpid))
            log.debug("handle_ip router_id {}; destination network {} is unreachable".format(self.connection.dpid, str(packet.payload.dstip)))
            self.send_icmp(3, 0, str(packet.payload.srcip), str(packet.src), in_port_data, packet)
        self.network.lock.release()

    def send_router_flow(self, dest_ip, packet_in, dest_port, dest_mac, drop):
        # install flow rule
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.in_port = packet_in.in_port
        fm.match.nw_dst = IPAddr(dest_ip)

        if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
            # Valid buffer ID was sent from switch, we do not need to encapsulate raw data in response
            fm.buffer_id = packet_in.buffer_id
        else:
            if packet_in.data is not None:
                # No valid buffer ID was sent but raw data exists, send raw data with flow_mod
                fm.data = packet_in.data
            else:
                return
        if not drop:
            if dest_mac:
                fm.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(dest_mac)))
                actions_str = "actions : dl_addr: " + str(dest_mac) + " dec_ttl , dest_port: " + str(dest_port.id)
            else:
                actions_str = "actions :  dec_ttl , dest_port: " + str(dest_port.id)
            fm.actions.append(nx.nx_action_dec_ttl())
            fm.actions.append(of.ofp_action_output(port=dest_port.id))

        else:
            actions_str = "actions : Drop rule."
        log.debug(
            "Add flow rule for router {}; matching fields => dl_type: ethernet.IP_TYPE, in_port: {}, nw_dst: {} ".format(
            self.connection.dpid, str(int(packet_in.in_port)), dest_ip) + actions_str)
        self.flow_rules.append((packet_in.in_port, dest_ip, dest_port, dest_mac))

        self.connection.send(fm)

    def handle_arp(self, packet, packet_in):
        self.network.lock.acquire()
        port = self.network.routers[self.connection.dpid].ports[packet_in.in_port]
        log.debug("GOT ARP packet, type: {}; in port_mac {}; from hwsrc {}; to hwdst: {};".format(packet.payload.opcode, port.mac,str(packet.payload.hwsrc),str(packet.payload.hwdst)))
        if packet.payload.opcode == arp.REQUEST and port.ip == str(packet.payload.protodst):
            my_arp = arp()
            my_arp.opcode = arp.REPLY
            my_arp.protosrc = IPAddr(port.ip)
            my_arp.protodst = packet.payload.protosrc
            my_arp.hwdst = packet.payload.hwsrc
            my_arp.hwsrc = EthAddr(port.mac)

            my_ether = ethernet()
            my_ether.type = ethernet.ARP_TYPE
            my_ether.dst = packet.payload.hwsrc
            my_ether.src = EthAddr(port.mac)
            my_ether.payload = my_arp
            log.debug("Sending ARP REPLY at router {}, to dest_ip {}; to port {};".format(self.connection.dpid, str(packet.payload.protosrc), port.id))
            self.send_packet(None, my_ether, packet_in.in_port, of.OFPP_NONE)

        elif packet.payload.opcode is arp.REPLY and port.mac == str(packet.payload.hwdst):
            log.debug("GOT ARP REPLY at router {}; from src_mac {}; src_ip {}; input_port {}".format(self.connection.dpid, str(packet.payload.hwsrc),packet.payload.protosrc, packet_in.in_port))
            if str(packet.payload.protosrc) in self.waiting_arp_requests:
                self.arp_cache[str(packet.payload.protosrc)] = (packet.payload.hwsrc, time.time())
                self.network.lock.release()
                self.handle_ip(self.waiting_arp_requests[str(packet.payload.protosrc)][0], self.waiting_arp_requests[str(packet.payload.protosrc)][1])
                self.network.lock.acquire()
                del self.waiting_arp_requests[str(packet.payload.protosrc)]
                # TODO: check if handle_ip call is
        self.network.lock.release()

    def send_arp_request(self, req_ip, port):
        my_arp = arp()
        my_arp.opcode = arp.REQUEST
        my_arp.protosrc = IPAddr(port.ip)
        my_arp.protodst = IPAddr(req_ip)
        my_arp.hwdst = EthAddr('FF:FF:FF:FF:FF:FF')
        my_arp.hwsrc = EthAddr(port.mac)

        my_ether = ethernet()
        my_ether.type = ethernet.ARP_TYPE
        my_ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
        my_ether.src = EthAddr(port.mac)
        my_ether.payload = my_arp

        self.send_packet(None, my_ether, port.id, of.OFPP_NONE)

    def send_icmp(self, tp, code, dest_ip, dest_mac, dest_port, orig_packet):
        # Should be able to send echo reply (tp=0,code=0),
        # destination unreachable (tp=3,code=0(network unreachable)/1(host unreachable)/3(port unreachable)),
        # TTL expired (tp=11,code=0)

        msg = None
        if tp == 0:
            p = orig_packet.payload
            while p is not None and not isinstance(p, echo):
                p = p.next
            if p is None:
                return
            r = echo(id=p.id, seq=p.seq)
            r.set_payload(p.next)
            msg = icmp(type=0, code=0)
            msg.set_payload(r)
        elif tp == 3:
            msg = icmp()
            msg.type = 3
            msg.code = code
            d = orig_packet.payload.pack()
            d = d[:orig_packet.payload.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d
            msg.payload = d
        elif tp == 11:
            msg = icmp()
            msg.type = 11
            msg.code = 0
            d = orig_packet.payload.pack()
            d = d[:orig_packet.payload.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d
            msg.payload = d

        # Make the IP packet around it
        ipp = ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = IPAddr(dest_port.ip)
        ipp.dstip = IPAddr(dest_ip)

        # Ethernet around that...
        e = ethernet()
        e.src = EthAddr(dest_port.mac)
        e.dst = EthAddr(dest_mac)
        e.type = e.IP_TYPE

        # Hook them up...
        ipp.payload = msg
        e.payload = ipp

        # send this packet to the switch
        log.debug('router {}; Sending ICMP TYPE {}; code {}; dest_ip {}; output_port {}'.format(self.connection.dpid, tp, code, dest_ip, dest_port.id))
        self.send_packet(None, e, dest_port.id, of.OFPP_NONE)
        # todo : check send_packet

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
        if self.connection.dpid in range(200, 300):
            self.act_like_switch(packet, packet_in)
        elif self.connection.dpid in range(100, 200):
            self.act_like_router(packet, packet_in)
        else:
            log.debug("INVALID DPID: {} and should be in range [100,299]".format(self.connection.dpid))

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

    def act_like_router(self, packet, packet_in):

        if packet.type == ethernet.IP_TYPE:
            log.debug("act_like_router: received IP_TYPE packet. src_ip {}; dest_ip {}; ttl {}".format(packet.payload.srcip, packet.payload.dstip, packet.payload.ttl))
            self.handle_ip(packet, packet_in)
        elif packet.type == ethernet.ARP_TYPE:
            self.handle_arp(packet, packet_in)
        else:
            return

    def act_like_switch(self, packet, packet_in):

        if packet.src in self.forward_table and packet_in.in_port != self.forward_table[packet.src]:
            self.remove_flow(packet.src)
        self.forward_table[packet.src] = packet_in.in_port

        if packet.dst in self.forward_table:
            log.debug('Found dest in table. Adding flow rule for Switch: {}; packet: dest = {}; src = {}; in_port = {}'.format(self.connection.dpid, packet.dst, packet.src, packet_in.in_port))
            self.send_flow_mod(packet, packet_in, self.forward_table[packet.dst])
        else:
            # FLOODING
            log.debug('Flooding packet in switch: {}; dest = {}; src = {}; in_port = {}'.format(self.connection.dpid, packet.dst, packet.src, packet_in.in_port))
            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

    def remove_flow(self, source):
        log.debug('Remove flow rule for :Switch {}; dl_dest = {}'.format(self.connection.dpid, source))
        fm = of.ofp_flow_mod()
        fm.command = of.OFPFC_DELETE
        fm.match.dl_dst = source # change this if necessary
        self.connection.send(fm) # send flow-mod message


def launch():
    """
    Starts the component
    """
    n = Network()

    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        t = Tutorial(event.connection)
        tutorial_list[event.connection.dpid] = t
        if event.connection.dpid in range(100, 200):
            n.set_tutorial(event.connection.dpid, t)

    core.openflow.addListenerByName("ConnectionUp", start_switch)


