from mininet.topo import Topo

def int2dpid( dpid ):
        try:
            dpid = hex( dpid )[ 2: ]
            dpid = '0' * ( 16 - len( dpid ) ) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

class Edge:
    """Represents an edge between two entities"""
    
    def __init__(self, left, right):
        self.left = left
        self.right = right

class WanTopology( Topo ):
    def __init__( self ):
        """Create custom topo."""

        Topo.__init__( self )

        # Set Node IDs for hosts and switches

        # Add Nodes
        routers = [
                self.addSwitch('r100', dpid=int2dpid(100)),
                self.addSwitch('r101', dpid=int2dpid(101)),
                self.addSwitch('r102', dpid=int2dpid(102))
            ]
        switches = [
                self.addSwitch('s200', dpid=int2dpid(200)),
                self.addSwitch('s201', dpid=int2dpid(201)),
                self.addSwitch('s202', dpid=int2dpid(202))
            ]
        hosts = [
                self.addHost('h1', ip='10.0.0.10/24'),
                self.addHost('h2', ip='10.0.0.20/24'),
                self.addHost('h3', ip='10.0.0.30/24'),
                self.addHost('h4', ip='10.0.1.40/24'),
                self.addHost('h5', ip='10.0.1.50/24'),
                self.addHost('h6', ip='10.0.1.60/24'),
                self.addHost('h7', ip='10.0.2.70/24'),
                self.addHost('h8', ip='10.0.2.80/24'),
                self.addHost('h9', ip='10.0.2.90/24')
        ]

        # Add Edges
        edges = [   
                    Edge(routers[0], switches[0]),
                    Edge(routers[1], switches[1]),
                    Edge(routers[2], switches[2]),
                    Edge(routers[0], routers[1]),
                    Edge(routers[1], routers[2]),
                    Edge(routers[2], routers[0]),
                    Edge(switches[0], hosts[0]),
                    Edge(switches[0], hosts[1]),
                    Edge(switches[0], hosts[2]),
                    Edge(switches[1], hosts[3]),
                    Edge(switches[1], hosts[4]),
                    Edge(switches[1], hosts[5]),
                    Edge(switches[2], hosts[6]),
                    Edge(switches[2], hosts[7]),
                    Edge(switches[2], hosts[8])
            ]

        for edge in edges:
            self.addLink( edge.left, edge.right )


topos = { 'WanTopology': ( lambda: WanTopology() ) }
