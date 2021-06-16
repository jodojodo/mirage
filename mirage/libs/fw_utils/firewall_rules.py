#!/usr/bin/env python3

from mirage.libs.ble_utils import packets
from mirage.libs import utils

class IncompatibleAttributeException(Exception):
    pass

class InvalidAttributeException(Exception):
    pass

class BLETablesRule:
    '''
    This class describes a firewall rule in the BLE_TABLES context.
    The following fields are supported, and bear the same name as in a rules file :

    +--------------+-----------+----------------------------------------+------------------------------------+
    | Name         | Mandatory | Values                                 | Description                        |
    +==============+===========+========================================+====================================+
    | action       | yes       | allow/deny                             | Allow or deny matching traffic     |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | type         | yes       | Valid Mirage BLE packet class          | Packet type to match               |
    |              |           | (see mirage/libs/ble_utils/packets.py) |                                    |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | handle       | no        | hexadecimal integer                    | Handle value to match              |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | value        | no        | hexadecimal integer                    | Value to match at specified handle |
    |              |           |                                        | (only usable if "handle" is set)   |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | direction    | no        | master/slave                           | Match only if the packet goes to   |
    |              |           |                                        | the specified role                 |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | src          | no        | BD Address                             | Match only if coming from the      |
    |              |           |                                        | specified address                  |
    +--------------+-----------+----------------------------------------+------------------------------------+
    | dst          | no        | BD Address                             | Match only if going to the         |
    |              |           |                                        | specified address                  |
    +--------------+-----------+----------------------------------------+------------------------------------+
    '''

    valid_keys={
            "handle":lambda kwargs:True,
            "value":lambda kwargs:"handle" in kwargs,
            "direction":lambda kwargs:True,
            "src":lambda kwargs:True,
            "dst":lambda kwargs:True,
            }


    def __init__(self, action, type, **kwargs):
        # may raise AttributeError if the type is invalid
        # may raise KeyError if an attribute name is unknown
        # may raise IncompatibleAttributeException in case of attribute incompatibility
        # may raise InvalidAttibuteException if action isn't allow or deny

        if action == "allow":
            self.action=True
        elif action == "deny":
            self.action=False
        else:
            raise InvalidAttibuteException(action)

        self.type=getattr(packets,type) # may raise AttributeError, catched above
        for key in kwargs:
            if BLETablesRule.valid_keys[key](kwargs): # may raise KeyError, catched above
                setattr(self, key, kwargs[key])
            else:
                raise IncompatibleAttributeException(key)

    def match(self, packet, fromMaster, srcAddr, dstAddr=None):
        # returns True if packet matches, False otherwise
        
        if not isinstance(packet, self.type):
            return False

        if hasattr(self, "handle"):

            if not hasattr(self, "handle"):
                return False

            if not packet.handle == utils.integerArg(self.handle):
                return False

            if hasattr(self, "value"):

                if not hasattr(packet, "value"):
                    return False

                
                try:
                    if not packet.value == utils.integerArg(self.value).to_bytes(len(packet.value),"little"):
                        return False
                except OverflowError:
                    return False

        if hasattr(self,"src"):
            if srcAddr != self.src.upper():
                return False

        if hasattr(self,"dst"):
            if (dstAddr==None) or (dstAddr != self.dst.upper()):
                return False

        if hasattr(self,"direction"):
            if fromMaster != (self.direction=="slave"):
                return False

        return True


