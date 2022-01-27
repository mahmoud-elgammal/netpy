import pytest

import time
from netpy.constants import ScanStatus
from netpy.netpy import NetPy

# @pytest.fixture()
class TestScan:
    " Test NetPy's Scanner Functionality "

    # @pytest.fixture
    def test_scan_range_ports(self):
        " Test Scanning a Range of Ports "

        netpy = NetPy()
        # Scan a range of ports
        netpy.set_ip("scanme.nmap.org")
        netpy.set_port("78-82")
        ports = netpy.scan()
        time.sleep(0.5)

        assert len(ports) == 4, "Scanning a range of ports should return 4 ports but found {}".format(len(ports))

        # Scan a single port
        for port in ports:
            if port.get("port") == 80:
                assert port.get("status") == ScanStatus.OPEN, "Scanning of port 80 should return only open ports"

            else:
                assert port.get("status") == ScanStatus.CLOSED, "Scanning of port 80 should return only closed ports"


    def test_scan_single_port(self):
        " Test Scanning a Single Port "

        netpy = NetPy()
        # Scan a range of ports
        netpy.set_ip("scanme.nmap.org")
        netpy.set_port("80")
        ports = netpy.scan()
        time.sleep(0.5)

        assert len(ports) == 1, "Scanning a single port should return 1 port but found {}".format(len(ports))

        # Scan a single port
        for port in ports:
            assert port.get("port") == 80, "Scanning of port 80 should return only port 80"
            assert port.get("status") == ScanStatus.OPEN, "Scanning of port 80 should return only open ports"

