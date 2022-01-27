import socket
import subprocess
import sys
import threading
import time
from pymitter import EventEmitter

from .constants import *
import csv

class NetPy(EventEmitter):
    def __init__(self):
        super().__init__()
        self.port = 0
        self.ports = []
        self.ip = "0.0.0.0"
        self.method = ScanMethod.TCP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.BUFFER_SIZE = 1024
        self.process = None
        pass

    def set_port(self, ports: int):
        self.port_start = 0
        self.port_end = 0

        if "-" in ports:
            self.port_start, self.port_end = ports.split("-")
            self.port_start = int(self.port_start)
            self.port_end = int(self.port_end)

        else:
            self.port_start = int(ports)
            self.port_end = int(ports)

    def set_ip(self, ip: str):
        self.ip = ip

    def set_timeout(self, timeout=0.5+1):
        self.timeout = timeout
        self.socket.settimeout(timeout)

    def set_verbose(self, verbose: bool):
        self.verbose = verbose

    def set_udp(self, udp: bool):
        if udp:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(self.timeout)
            self.method = ScanMethod.UDP

    # def set_prog(self):
    #     self.process = subprocess.Popen(['C:\\Windows\\system32\\cmd.exe'])

    def _scan(self, push_port, port):
        try:
            self.socket.connect((self.ip, port))
            if self.method == ScanMethod.UDP:
                self.socket.send(bytes(0))
                self.socket.recv(1024)

            push_port(port, ScanStatus.OPEN)

        except socket.timeout:
            if self.method == ScanMethod.UDP:
                push_port(port, ScanStatus.OPEN_FILTERED)
            elif self.method == ScanMethod.TCP:
                push_port(port, ScanStatus.FILTERED)

        except socket.error:
            if self.method == ScanMethod.UDP:
                push_port(port, ScanStatus.CLOSED_FILTERED)
            elif self.method == ScanMethod.TCP:
                push_port(port, ScanStatus.CLOSED)

        finally:
            pass

    def scan(self):
        ports = []
        threads = []

        f = open("./resources/service-names-port-numbers.csv", "r")
        serices = [{k: v for k, v in row.items()}
        for row in csv.DictReader(f, skipinitialspace=True)]
        f.close()

        def push_port(port, status):
            result = {"port": port, "status": status}
            found = False

            if status != ScanStatus.CLOSED:
                for service in serices:
                    if (service["Port Number"]) == str(port) and service["Transport Protocol"].upper() == self.method.name:
                        result["service"] = service["Service Name"]
                        result["description"] = service["Description"]
                        result["notes"] = service["Assignment Notes"][:100]
                        found = True

            if not found:
                result["service"] = "unknown"
                result["description"] = "unknown"
                result["notes"] = "unknown"

            ports.append(result)
            self.emit("scan", result)

        if self.port_start == self.port_end:
            self._scan(push_port, self.port_start)

        else:
            for port in range(self.port_start, self.port_end):
                # thread = threading.Thread(target=self._scan, args=(push_port, port,))
                # thread.start()
                # threads.append(thread)
                self._scan(push_port, port)

        self.emit("scan_end", ports)
        self.stop()

        # for thread in threads:
        #     thread.join()

        return ports

    def listen(self):
        self.socket.bind((self.ip, self.port_start))
        self.socket.listen(1)
        print('listening on {}:{}'.format(self.ip, self.port_start))

        conn, _ = self.socket.accept()

        while 1:
            data = conn.recv(1024)

            if not data:
                break

            print("recived:", self.s(data))

            if self.prog:
                self.process()

            msg = input("send: ")
            if msg == "q":
                break

            conn.send(self.p(msg).encode())
        conn.close()

    def readlines(self, process):
        while process.poll() is None:
            time.sleep(1)
            sys.stdout.write(process.stdout.readline().decode())

    def connect(self):
        # self.socket.connect((self.ip,  self.port_start))
        print('connected to {}:{}'.format(self.ip, self.port_start))
        process = subprocess.Popen(['C:\\Windows\\system32\\cmd.exe', ''],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print(process.stdout.readline().decode())

    def stop(self):
        self.socket.close()
        # self.process.kill()
        self.emit("stop")

    def p(self, msg: str) -> str:
        return msg + " " * (self.BUFFER_SIZE - len(msg))

    def s(self, msg: bytes) -> str:
        return msg.decode("utf-8").strip()

    def __str__(self):
        return 'netcat({}:{})'.format(self.ip, self.port_start)

    def __repr__(self):
        return '<{}>'.format(self)

    def run(self):
        pass