import whois21 
from pathlib import Path
from dns import resolver, reversename


class SocketIP:
    connection_dict = {}
    def __init__(self, proto, ip_list, port):
        self.connection_dict["proto"] = proto
        self.connection_dict["ip-list"] = ip_list
        self.connection_dict["port"] = port


    def is_default_ip(self):
        return (sum(self.connection_dict["ip-list"]) == 0) and (self.connection_dict["port"] == 0)


    def get_str_ip(self):
        return ".".join(map(str, self.connection_dict["ip-list"]))


    def get_port(self):
        return self.connection_dict["port"]


    def get_proto(self):
        return self.connection_dict["proto"]


    def get_dict(self):
        printable_dict = {}
        printable_dict["proto"] = self.get_proto()
        printable_dict["ip"] = self.get_str_ip()
        printable_dict["port"] = str(self.get_port())
        printable_dict["network-details"] = self.connection_dict["network-details"]
        return printable_dict
    

    def init_network_details(self):
        raw_network_details = whois21.WHOIS(self.get_str_ip())    
        self.connection_dict["network-details"] = raw_network_details.whois_data
        self.connection_dict["network-details"]["reverse-lookup"] = self.get_reverse_lookup()
        try:
            self.connection_dict["network-details"].pop("COMMENT")
            self.connection_dict["network-details"].pop("REMARKS")
        except KeyError as e:
            pass


    def get_reverse_lookup(self):
        addr_to_lookup = reversename.from_address(self.get_str_ip())
        rdns_result = ""
        try:
            dn_query = resolver.resolve(addr_to_lookup, "PTR")[0]
            rdns_result = str(dn_query)
        except resolver.NXDOMAIN as e:
            rdns_result = "DNS name does not exist"
        return rdns_result

