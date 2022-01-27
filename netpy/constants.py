from enum import Enum

class ScanMethod(Enum):

    TCP = 'TCP'
    UDP = 'UDP'


class ScanStatus(Enum):

    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'
    OPEN_FILTERED = 'Open | Filtered'
    CLOSED_FILTERED = 'Closed | Filtered'
    UNKNOWN = 'Unknown'