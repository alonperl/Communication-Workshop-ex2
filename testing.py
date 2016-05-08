import threading
from priority_dict import priority_dict
class Network(object):
    #__metaclass__ = SingletonType

    class Router(object):
        def __init__(self, dpid):
            self.dpid = dpid
            self.ports = {}  # id:ports(object)

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

a= Network()
print a.compute_ospf()