"""
Authors:
David Saper - 302598032 dav_sap
Alon Perelmuter - 20063088 alonperl
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
import threading
from pox.core import core
import pox.openflow.libopenflow_01 as of
import utils
from pox.lib.packet.lldp import lldp, chassis_id, port_id, ttl, end_tlv
from pox.lib.packet.ethernet import ethernet
log = core.getLogger()
tutorial_list = []

class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__ (self, connection):
        self.forward_table = {}
        self.connection = connection
        self.unauthorized_ports = []
        # self.discovery = Discovery()
        # Discovery.get_node(connection.dpid).connection = connection
        # This binds our PacketIn event listener
        connection.addListeners(self)
    def update_flow_table(self):
        """
        This function goes over all ports found in unauthorized_port (port that are
        forbidden from graph because of the spanning tree.) and ask remove_rules_by_port
        to remove all the flows holding the forbidden ports.
        """
        # log.debug('update flow table for switch {}'.format(self.connection.dpid))
        for port in self.unauthorized_ports:
            self.remove_rules_by_port(port)

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        if event.parsed.type == ethernet.LLDP_TYPE:
            return
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
        """
        This function install a flow for a specific request to the switch
        """
        log.debug("Installing new flow rule on SW: {}; in_port: {}; dl_src: {}; dl_dst: {}".format(self.connection.dpid, packet_in.in_port, packet.src,packet.dst))
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
        """
        This function manage the forwarding table of the switch.
        the func. gets the packet the the switch passed to the controller,
        and decide whether to ignore the packet or install a new flow to the switch,
        or just flood the packet.
        """
        if packet_in.in_port in self.unauthorized_ports:
            log.debug("SW " + str(self.connection.dpid) + " got packet from unauthorized port " + str(packet_in.in_port))
            return
        if packet.src in self.forward_table and packet_in.in_port != self.forward_table[packet.src]:
            self.remove_flow(packet.src)
        self.forward_table[packet.src] = packet_in.in_port
        if packet.dst in self.forward_table:
            self.send_flow_mod(packet, packet_in, self.forward_table[packet.dst])
        else:
            ####FLOODING packet
            ports_list = self.connection.features.ports
            log.debug('SW:' + str(
                self.connection.dpid) + '; Flooding packet: dest = {}; src = {}; from in_port = {}; to all ports except '
                                        'unauthorized = {}'.format(packet.dst, packet.src, packet_in.in_port, self.unauthorized_ports))
            for port in ports_list:
                if port.port_no not in self.unauthorized_ports and \
                                port.port_no < of.OFPP_MAX and \
                                port.port_no != packet_in.in_port:
                    self.send_packet(None, packet_in.data, port.port_no, packet_in.in_port)

    def remove_flow(self, source):
        """
        This function removes a flow from the switch by source mac address.
        It helps while links are turn off
        """
        log.debug('Remove flow from SW: {} ; dl_dest = {}'.format(self.connection.dpid, source))
        fm = of.ofp_flow_mod()
        fm.command = of.OFPFC_DELETE
        # fm.match.dl_dst = source # change this if necessary
        fm.match.dl_dst = source  # change this if necessary
        self.connection.send(fm) # send flow-mod message

    def remove_rules_by_port(self, port):
        """
        This function removes a flow from the switch according to a given port number.
        It helps while removing edged in the graph.
        it will clean all the flows in the switch that connected to the port
        """
        log.debug("Remove flow from SW: {} out_port:{}".format(self.connection.dpid,port))
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE, out_port=port)
        self.connection.send(msg)
        mac_to_remove = []
        for mac, in_port in self.forward_table.iteritems():
            if in_port == port:
                mac_to_remove.append(mac)
                fm = of.ofp_flow_mod()
                fm.command = of.OFPFC_DELETE
                fm.match.dl_src = mac
                self.connection.send(fm)
        for mac in mac_to_remove:
            del self.forward_table[mac]


class Discovery(object):
    __metaclass__ = utils.SingletonType
    LLDP_INTERVAL = 1
    TIME_TO_REMOVE = 6
    LLDP_DST_ADDR = '\x01\x80\xc2\x00\x00\x0e'
    def __init__(self):
        core.openflow.addListeners(self)
        self.topology = utils.Graph()
        self.edge_timer = utils.Timer(3,self.run_edges,recurring=True)
        self.lock = threading.Lock()
        self.sub_tree = []



    def is_port_active(self, node, port):
        """"
        This function gets a Node and a port number, It will go over the sub_tree,
        (sub_tree is the kruskal minimum spanning tree) and will return if the given
        port is a forbidden port.
        :return:
            True : if link is active
            False: if link is forbidden
        """
        for edge in self.sub_tree:
            if node in edge:
                if self.topology.nodes[node][port][0] in edge:
                    return True
        return False
    def _handle_ConnectionUp(self, event):
        """"
        Will be called when a switch is added. Use event.dpid for switch ID,
        and event.connection.send(...) to send messages to the switch.
        """
        timer = utils.Timer(Discovery.LLDP_INTERVAL,self._send_lldp,args=[event],recurring=True)
        log.debug("New switch ConnectionUp dpid: {}".format(event.dpid))
        self.lock.acquire()
        node = utils.Node(event.dpid)
        self.set_tutorial(node, event.connection)

        self.topology.add_node(node, {})
        self.lock.release()
        #send flow to the switch to pass every lldp packet to the controller
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.LLDP_TYPE
        fm.match.dl_dst = self.LLDP_DST_ADDR
        # it is not mandatory to set fm.data or fm.buffer_id
        action = of.ofp_action_output(port=of.OFPP_CONTROLLER)
        fm.actions.append(action)
        # Send flow to the switch
        event.connection.send(fm)

    @staticmethod
    def set_tutorial(node, connection):
        """"
        connect given node to his real Tutorial.
        """
        for tuto in tutorial_list:
            if tuto.connection == connection:
                node.tutorial = tuto
                return True
        return False
    def _handle_ConnectionDown(self, event):
        """"
        Will be called when a switch goes down. Use event.dpid for switch ID.
        """
        log.debug("_handle_ConnectionDown: dpid {}".format(event.dpid))
        self.lock.acquire()
        node = self.get_node(event.dpid)
        far_ends = []
        for port, port_data in self.topology.nodes[node].iteritems():
                far_ends.append(port_data[0])
        for far in far_ends:
            self.remove_edge((node, far))
        self.topology.remove_node(node)
        self.Kruskal_Mst()
        self.lock.release()

    def _handle_PortStatus(self, event):
        """"
        Will be called when a link changes. Specifically, when event.ofp.desc.config is 1,
        it means that the link is down. Use event.dpid for switch ID and event.port for port number.
        """
        log.debug("_handle_PortStatus: SW {} port{}; status {}".format(event.dpid, event.port, event.ofp.desc.config))
        if event.ofp.desc.config == 1:
            #port is down
            self.lock.acquire()
            node = self.get_node(event.dpid)
            if event.port in self.topology.nodes[node]:
                far_node = self.topology.nodes[node][event.port][0]
                edge = (node, far_node)
                self.remove_edge(edge)
                log.debug("Removed edge (sw{})<>(sw{}); Reason: ports are down".format(str(node),str(far_node)))
                # log.debug(str(far_node) +self.ports_dict_to_string(self.topology.nodes[far_node]))
                self.Kruskal_Mst()
            # else:
                # log.debug("Trying to remove a not active edge : Switch {} port{}".format(event.dpid, event.port))
            self.lock.release()




    def _handle_PacketIn(self, event):
        """"
        Will be called when a packet is sent to the controller. Same as in the previous part.
        Use it to find LLDP packets (event.parsed.type == ethernet.LLDP_TYPE) and update
        the topology according to them.
        """
        if event.parsed.type != ethernet.LLDP_TYPE:
            return

        pkt = event.parsed
        lldp_p = pkt.payload
        ch_id = lldp_p.tlvs[0]
        po_id = lldp_p.tlvs[1]

        r_dpid = int(ch_id.id)
        r_port = int(po_id.id)
        # log.debug("Discovery _handle_PacketIn to dpid {} from Sw{}port{}".format(event.dpid, r_dpid, r_port))
        self.lock.acquire()
        node = self.get_node(event.dpid)
        far_node = self.get_node(r_dpid)
        if self.topology.get_edge(node, far_node):
            self.topology.update_edge(node, far_node, time.time())
        else:
            log.debug("Discovered new edge: (sw: " + str(node) + "; port: " + str(event.port) + ") <> (sw: " + str(
                r_dpid) + "; port: " + str(r_port) + ")")
            self.topology.add_edge(node,far_node,time.time())
            self.topology.nodes[node][event.port] = (far_node,r_port)
            self.topology.nodes[far_node][r_port] = (node, event.port)
            self.Kruskal_Mst()
        self.lock.release()

    def ports_dict_to_string(self,ports):
        """"
        This function gets a dictionary of ports and return a string of all the nodes.
        raised for log reasons.
        """
        str_ports = ''
        for port,far in ports.iteritems():
            str_ports += "p:" + str(port) + " far_node:"+str(far[0]) + " far_port:"+str(far[1])
        return str_ports

    def _send_lldp(self, event ):
        """"
        """""
        # log.debug('Flooding packet : dest = {} src = {} in_port = {}'.format(packet.dst, packet.src, packet_in.in_port))
        # self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        # log.debug("send lldp sw : {}".format(event.dpid))
        dst = Discovery.LLDP_DST_ADDR		# == '\x01\x80\xc2\x00\x00\x0e'

        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:
                # Build LLDP packet
                src = str(p.hw_addr)
                port = p.port_no

                lldp_p = lldp() # create LLDP payload
                ch_id = chassis_id() # Add switch ID part
                ch_id.subtype = 1
                ch_id.id = str(event.dpid)
                lldp_p.add_tlv(ch_id)
                po_id = port_id() # Add port ID part
                po_id.subtype = 2
                po_id.id = str(port)
                lldp_p.add_tlv(po_id)
                tt = ttl() # Add TTL
                tt.ttl = Discovery.LLDP_INTERVAL # == 1
                lldp_p.add_tlv(tt)
                lldp_p.add_tlv(end_tlv())

                ether = ethernet() # Create an Ethernet packet
                ether.type = ethernet.LLDP_TYPE # Set its type to LLDP
                ether.src = src # Set src, dst
                ether.dst = dst
                ether.payload = lldp_p # Set payload to be the LLDP payload

                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = ether
                event.connection.send(pkt)
    def run_edges(self):
        """"
        scan timestamps of all edges. If an edge was not seen for more than 6 seconds, remove it from the topology.
        """
        self.lock.acquire()
        edges_to_remove = []
        for edge,data in self.topology.edges.iteritems():
            if time.time()-data > Discovery.TIME_TO_REMOVE:
                log.debug("Removed edge (sw{}<>sw{}); Reason: LLDP not arrived for long time. timeout. : "
                          "".format(edge[0].dpid,edge[1].dpid) )
                edges_to_remove += [edge]
        if edges_to_remove:
            for e in edges_to_remove:
                self.remove_edge(e)
            self.Kruskal_Mst()

        self.lock.release()

    def remove_edge(self, edge):
        # del information from nodes
        port0 = -1
        port1 = -1
        log.debug("remove edge ({},{})".format(edge[0],edge[1]))
        for port, port_data in self.topology.nodes[edge[0]].iteritems():
            if port_data[0] == edge[1]:
                log.debug("empty the ports " + str(port) + str(port_data[0].dpid))
                port0 = port
                port1 = port_data[1]
        del self.topology.nodes[edge[0]][port0]
        edge[0].tutorial.remove_rules_by_port(port0)
        del self.topology.nodes[edge[1]][port1]
        edge[1].tutorial.remove_rules_by_port(port1)
        # remove edge
        self.topology.delete_edge(edge[0], edge[1])
    def get_node(self, dpid):
        for node in self.topology.nodes:
            if node.dpid == dpid:
                return node

    def Kruskal_Mst(self):
        """"
        This function calculate the minimum spanning tree by kruskal algorithm
        it will update the self.sub_tree with his decision.
        It also calls for update_unauthorized_ports that will update all the nodes
        of the graph by the MST demands.
        """
        self.sub_tree = []
        uf = utils.UnionFind()
        for v in self.topology.nodes:
            uf.make_set(v)
        for edge in self.topology.edges:
            if uf.find(edge[0]) != uf.find(edge[1]):
                self.sub_tree.append((edge[0],edge[1]))
                uf.union(edge[0],edge[1])
        log.debug("Kruskal full graph: {}".format(self.edges_to_str(self.topology.edges)))
        log.debug("Kruskal MST: {} [these are the active links]".format(self.edges_to_str(self.sub_tree)))
        self.update_unauthorized_ports()

    def edges_to_str(self,edges):
        """"
        :return: string of all the edges
        """
        str_to_print = ''
        for edge in edges:
            str_to_print += '(' + str(edge[0]) + "," + str(edge[1]) + ") "
        return str_to_print

    def update_unauthorized_ports(self):
        """"
        This Function will go over all the nodes and will update all the unauthorized ports
        it will call updae_flow_table of each node that will update his flow table.
        """
        for node, ports in self.topology.nodes.iteritems():
            node.tutorial.unauthorized_ports = []
            for port in ports:
                if not self.is_port_active(node, port):
                    node.tutorial.unauthorized_ports.append(port)
            log.debug("sw: " + str(node) + "; unauthorized ports by ST are: " + str(node.tutorial.unauthorized_ports))
            node.tutorial.update_flow_table()

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        t = Tutorial(event.connection)
        tutorial_list.append(t)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.register('discovery', Discovery())

