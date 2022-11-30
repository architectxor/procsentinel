from SocketIP import *
from cfts import *
import random, time, bintropy


class AnalyzedProcess:
    ap_dict = {}

    def __init__(self, pid_path, store_path):
        self.init_assesment_params()
        self.init_proc_info(pid_path)
        self.init_log_params(store_path)
        self.analyze()
        self.evaluate()


    def init_assesment_params(self):
        self.ap_dict["sus-value"] = 0
        self.ap_dict["mitre"] = []
        self.ap_dict["rcl-flag"] = 0


    def init_log_params(self, store_path):
        self.ap_dict["ml-path"] = store_path / "main_log"
        self.generate_unique_path(store_path)


    def analyze(self):
        self.analyze_sections_permissions()
        if isinstance(self.ap_dict["exe-path"], Path):
            self.analyze_altered_sections()
            self.analyze_software_packaging()


    def evaluate(self):
        self.calc_sus_rate()


    # General Process information
    def init_proc_info(self, pid_path):
        self.ap_dict["pid"] = pid_path.parts[-1]
        self.ap_dict["pid-path"] = pid_path
        self.ap_dict["unid"] = self.get_unique_id()
        self.init_pname()
        self.init_exe_path()
        self.init_process_connections()
        self.init_wx_sections()


    def init_pname(self):
        PROC_NAME_COL = 1
        stat_path = self.ap_dict["pid-path"] / "stat"
        stat_path = stat_path.resolve()
        with stat_path.open() as stat:
            self.ap_dict["pname"] = stat.read().split()[PROC_NAME_COL]


    def init_exe_path(self):
        exe_symlink_path = self.ap_dict["pid-path"] / "exe"
        try:
            exe_path = exe_symlink_path.resolve()
        except FileNotFoundError as e:
            exe_path = -1
            self.ap_dict["sus-value"] += SUS_CFTS["NO_EXE"]
        self.ap_dict["exe-path"] = exe_path


    def get_pid(self):
        return self.ap_dict["pid"]


    def generate_unique_path(self, store_path):
        valid_pname = self.ap_dict["pname"].strip("()").replace("/", "_")
        unique_path = store_path / "-".join([self.ap_dict["pid"], valid_pname, self.ap_dict["unid"]])
        self.ap_dict["unique-path"] = unique_path


    # let's call it API
    def write(self):
        mitre_str = ""
        if self.ap_dict["mitre"]:
            mitre_str = self.get_mitre_formatted()
        log_str = self.get_log_str()

        with self.ap_dict["ml-path"].open("at") as main_log:
            main_log.write(log_str + "\n")
            main_log.write(mitre_str)

        with self.ap_dict["unique-path"].open("at") as detailed_log:
            detailed_log.write(log_str + "\n\n")
            detailed_log.write(mitre_str + "\n\n")
            detailed_log.write(self.get_wx_string() + "\n\n")
            if "alt-sections" in self.ap_dict.keys():
                detailed_log.write(self.get_alt_sections_str() + "\n\n")
            detailed_log.write(self.get_connections_string() + "\n\n")


    def terminate(self):
        pid = self.ap_dict["pid"]
        unid = self.ap_dict["unid"]
        time = self.get_time()
        term_str = f"{pid} PID terminated at {time} (UniqueID: {unid})\n"
        with self.ap_dict["ml-path"].open("at") as main_log:
            main_log.write(term_str)

        with self.ap_dict["unique-path"].open("at") as detailed_log:
            detailed_log.write("\n" + term_str)


    def get_time(self):
        return time.asctime(time.localtime(time.time())).split()[3]


    def get_log_str(self):
        log_str = ""
        pname = self.ap_dict["pname"]
        pid = self.ap_dict["pid"]
        unique_id = self.ap_dict["unid"]
        time = self.get_time()
        exe_state = "%no exe found%"
        sus_rate = self.ap_dict["sus-rate"]
        if isinstance(self.ap_dict["exe-path"], Path):
            exe_state = str(self.ap_dict["exe-path"])
        log_str = f"[{time}] [PID:{pid}]\t{unique_id}\t{sus_rate}%\t\t{pname}| {exe_state}"
        return log_str


    def get_unique_id(self):
        return str(hex(random.randint(0, 9999999)))[2:]


    # External connections block
    def init_process_connections(self):
        self.ap_dict["external-connections"] = []
        self.ap_dict["external-connections"].extend(self.get_process_sockets("udp"))
        self.ap_dict["external-connections"].extend(self.get_process_sockets("tcp"))
        self.exclude_default_ips()
        self.query_whois_for_connections()
        self.turn_connections_into_dicts()


    def exclude_default_ips(self):
        filtered = []
        for connection in self.ap_dict["external-connections"]:
            if connection.is_default_ip():
                continue
            filtered.append(connection)
        self.ap_dict["external-connections"] = filtered


    def query_whois_for_connections(self):
        for connection in self.ap_dict["external-connections"]:
            connection.init_network_details()


    def turn_connections_into_dicts(self):
        dict_connections = []
        for connection in self.ap_dict["external-connections"]:
            dict_connections.append(connection.get_dict())
        self.ap_dict["external-connections"] = dict_connections


    def get_process_sockets(self, proto):
        REMOTE_ADDR_COL = 2
        proto_list = ["udp", "tcp"]
        if not (proto in proto_list):
            raise ValueError(f"Specified unsupported proto: {proto}")

        sockets_path = self.ap_dict["pid-path"] / "net" / proto
        sockets_path = sockets_path.resolve()
        sockets = []
        with sockets_path.open() as socket_info:
            socket_info.readline()    # skip first, because it is table header
            for connection_line in socket_info:
                mangled_socket_str = connection_line.split()[REMOTE_ADDR_COL]
                demangled_socketIP = self.get_demangled_socket(proto, mangled_socket_str)
                sockets.append(demangled_socketIP)
        return sockets


    def get_demangled_socket(self, proto, mangled_socket_str):
        SRC_RADIX = 16
        IP_INDEX = 0
        PORT_INDEX = 1
        mangled_sock_list = mangled_socket_str.split(":")
        try:
            port = int(mangled_sock_list[PORT_INDEX], base=SRC_RADIX) 
        except ValueError as e:
            port = -1

        def do_get_octets_list(hex_ip, res):
            if len(hex_ip) <= 0:
                return res
            res.append(int(hex_ip[-2:], base=SRC_RADIX))
            return do_get_octets_list(hex_ip[:-2], res)

        def get_octets_list(hex_ip):
            return do_get_octets_list(hex_ip, [])

        return SocketIP(proto, get_octets_list(mangled_sock_list[IP_INDEX]), port)


    def get_connections_string(self):
        connections_str = "\t\t---CONNECTIONS START---\n"
        for connection in self.ap_dict["external-connections"]:
            proto = connection["proto"]
            ip = connection["ip"]
            port = connection["port"]
            socket_line = f"{proto}\t{ip}:{port}\n"
            for key in connection["network-details"].keys():
                nd_line = "\t" + key + ":\t\t" + str(connection["network-details"][key]) + "\n"
                socket_line = socket_line + nd_line
            connections_str = connections_str + socket_line + "\n"
        return connections_str + "\t\t---CONNECTIONS END---\n"


    # WX Permissions Block
    def init_wx_sections(self):
        self.ap_dict["wx-sections"] = self.get_wx_sections()


    def get_wx_sections(self):
        wx_sections = []
        maps_path = self.ap_dict["pid-path"] / "maps"
        with maps_path.open() as maps:
            for region_line in maps:
                PERM_COL = 1
                SECT_NAME_COL = 5
                ADDR_RANGE_COL = 0
                region_list = region_line.split()
                INSERT_COL = SECT_NAME_COL if len(region_list) >= 6 else ADDR_RANGE_COL
                if "wx" in region_list[PERM_COL]:
                    wx_sections.append(region_line)
        return wx_sections


    def analyze_sections_permissions(self):
        if self.ap_dict["wx-sections"]:
            self.ap_dict["sus-value"] += SUS_CFTS["CODE_WX"]
            self.ap_dict["rcl-flag"] += 1
            if self.rcl_detected():
                self.ap_dict["mitre"].append(MITRE["REF_CODE_LD"])


    def rcl_detected(self):
        return self.ap_dict["rcl-flag"] == 2


    def get_wx_string(self):
        res = ["\t\t---SUSPICIOUS SECTIONS START---\n"]
        res.extend(self.ap_dict["wx-sections"])
        res.append("\n\t\t---SUSPICIOUS SECTIONS END---\n")
        res = "".join(res)
        return res


    # Scan code section block
    def analyze_altered_sections(self):
        altered_sections = self.get_altered_sections()
        if altered_sections:
            self.ap_dict["alt-sections"] = altered_sections
            self.ap_dict["sus-value"] += SUS_CFTS["CODE_DIFFERS"]
            self.ap_dict["rcl-flag"] += 1
            if self.rcl_detected():
                self.ap_dict["mitre"].append(MITRE["REF_COD_LD"])


    def get_altered_sections(self):
        altered_sections = []
        pid_path = self.ap_dict["pid-path"]
        maps_file = (pid_path / "maps").open("r")
        mem_file = (pid_path / "mem").open("rb", 0)
        for maps_line in maps_file:
            SRC_RADIX = 16
            PERMS_COL = 1; OFFSET_COL = 2; FILE_PATH_COL = 5
            maps_line_list = maps_line.split()
            permissions = maps_line_list[PERMS_COL]
            offset = int(maps_line_list[OFFSET_COL], SRC_RADIX)
            if len(maps_line_list) >= 6 and ("x" in permissions) and offset != 0:
                region_range = maps_line_list[0].split("-")
                start = int(region_range[0], SRC_RADIX)
                end = int(region_range[1], SRC_RADIX)
                size = end - start
                mem_file.seek(start)
                proc_region_bytes = mem_file.read(size)
                source_file = open(maps_line_list[FILE_PATH_COL], 'rb', 0)
                source_file.seek(offset)
                src_file_bytes = source_file.read(size)
                for i in range(size):
                    if src_file_bytes[i] != proc_region_bytes[i]:
                        altered_sections.append(maps_line)
        maps_file.close()
        mem_file.close()
        return altered_sections


    def get_alt_sections_str(self):
        res = ["\t\t---ALTERED SECTIONS START---\n"]
        res.append("\n".join(self.ap_dict["alt-sections"]))
        res.append("\n\t\t---ALTERED SECTIONS END---\n")
        return "".join(res)


    def get_mitre_formatted(self):
        res = "\n"
        pid = self.ap_dict["pid"]
        for mitre_ttp in self.ap_dict["mitre"]:
            res + mitre_ttp.format(pid) + "\n"
        return res


    # Packaging detection
    def analyze_software_packaging(self):
        AVG = 6.078
        HIGH = 7.553
        if bintropy.bintropy(self.ap_dict["exe-path"], 
                             threshold_average_entropy=AVG,
                             threshold_highest_entropy=HIGH):
            self.ap_dict["sus-value"] += SUS_CFTS["EXE_PKD"]
            self.ap_dict["mitre"].append(MITRE["SW_PACKAGIN"])
        

    # Digital Signature validation


    # Assessment
    def calc_sus_rate(self):
        self.ap_dict["sus-rate"] = self.ap_dict["sus-value"] * CFT_TOTAL / 100

