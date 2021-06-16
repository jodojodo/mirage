#!/usr/bin/env python3
from mirage.libs import io
from mirage.libs.ble_utils import packets
import tempfile
import os

class IncorrectBLETableError(RuntimeError):
    pass


def tokenize_line(line):
    while "  " in line:
        line=line.replace("  "," ")
    return line.split(" ")


def parse_ble_tables(lines):
    io.info("Parsing BLE_TABLES...")
    
    resulting_code = ""
    default=None
    i=0
    n=len(lines)

    while i<n:
        
        line=lines[i]

        # EXIT LOOP WHEN END FLAG IS REACHED
        if line=="END BLE_TABLES":
            break

        tokens=tokenize_line(line)

        if tokens[0]=="default":
            if len(tokens)!=2 or tokens[1] not in ("allow","deny"):
                raise IncorrectBLETableError("Invalid default rule : {}".format(line))
            if default!=None:
                raise IncorrectBLETableError("Several default rules in BLE_TABLES context")
            default=(tokens[1]=="allow")
        
        else:
            fct_args=", ".join("{} = '{}'".format(tokens[i*2],tokens[i*2+1].replace("'","\\'")) for i in range(len(tokens)//2))

            try:
                rule_type=tokens[tokens.index("type")+1]
            except IndexError:
                io.fail('Malformed rule : missing "type" value')
                raise
            except ValueError:
                raise IncorrectBLETableError('Invalid rule : missing "type"')

            resulting_code+="\n\t\t\tself.rule_dictionnary[\"{}\"].append(firewall_rules.BLETablesRule({}))".format(rule_type[3:],fct_args)

        i+=1

    if i==n:
        raise IncorrectBLETableError("Syntax error in BLE_TABLES : no END")
    if default==None:
        raise IncorrectBLETableError("No default rule in BLE_TABLES")

    resulting_code+="\n\t\t\tself.default_rule = {}".format(default)

    return lines[i+1:],resulting_code

def parse_gatt_filter(lines):
    io.info("Parsing GATT_FILTER...")

    resulting_code = ""
    i=0
    n=len(lines)

    while i<n:
        
        line=lines[i]

        # EXIT LOOP WHEN END FLAG IS REACHED
        if line=="END GATT_FILTER":
            break

        tokens=tokenize_line(line)


        try:
            uuid=tokens[tokens.index("uuid")+1]
        except IndexError:
            io.fail('Malformed rule : missing "uuid" value')
            raise
        except ValueError:
            raise IncorrectBLETableError('Invalid rule : missing "uuid"')

        resulting_code+="\n\t\tself.removedUUIDs.add(utils.integerArg('{}'))".format(uuid)

        i+=1

    if i==n:
        raise IncorrectBLETableError("Syntax error in GATT_FILTER : no END")

    return lines[i+1:],resulting_code
    

def parse_rules(ble_tables_content):
    lines=[]
    for line in ble_tables_content.strip().split("\n"):
        if "//" in line:
            line=line.split("//")[0]
        if line.strip()!="":
            lines.append(line.strip())

    rules_dict=""
    code_callbacks=""
    
    for elt_name in dir(packets):
        elt=getattr(packets,elt_name)
        if type(elt)==type and issubclass(elt,packets.BLEPacket) and elt!=packets.BLEPacket and "connectionHandle" in elt.__init__.__code__.co_names:
            rules_dict+="\n\t\tself.rule_dictionnary[\"{}\"]=[]".format(elt.__name__[3:])

            # -- code for packets from the Master --
            code_callbacks+="\n\tdef onMaster{}(self,packet):".format(elt.__name__[3:])
            code_callbacks+="\n\t\ttest=self.translateHandlesFromMaster(packet)"
            code_callbacks+="\n\t\tif not test:"
            code_callbacks+="\n\t\t\treturn False"
            code_callbacks+="\n\t\tres=self.default_rule"
            code_callbacks+="\n\t\tsrcAddr,dstAddr=self.connection2addresses(packet, True)"
            code_callbacks+="\n\t\tfor rule in self.rule_dictionnary[\"{}\"]:".format(elt.__name__[3:])
            code_callbacks+="\n\t\t\tif rule.match(packet, True, srcAddr, dstAddr):"
            code_callbacks+="\n\t\t\t\tres=rule.action"
            code_callbacks+="\n\t\t\t\tbreak"
            code_callbacks+="\n\t\tif not res:"
            code_callbacks+="\n\t\t\tio.info('Packet dropped by firewall : '+packet.__repr__())"
            code_callbacks+="\n\t\t\tself.errorResponse(packet)"
            code_callbacks+="\n\t\treturn res\n"

            # -- code for packets from the Slave --
            code_callbacks+="\n\tdef onSlave{}(self,packet):".format(elt.__name__[3:])
            code_callbacks+="\n\t\tif not self.mitmRunning:"
            code_callbacks+="\n\t\t\treturn True"
            code_callbacks+="\n\t\ttest=self.translateHandlesFromSlave(packet)"
            code_callbacks+="\n\t\tif not test:"
            code_callbacks+="\n\t\t\treturn False"
            code_callbacks+="\n\t\tres=self.default_rule"
            code_callbacks+="\n\t\tsrcAddr,dstAddr=self.connection2addresses(packet, False)"
            code_callbacks+="\n\t\tfor rule in self.rule_dictionnary[\"{}\"]:".format(elt.__name__[3:])
            code_callbacks+="\n\t\t\tif rule.match(packet, False, srcAddr, dstAddr):"
            code_callbacks+="\n\t\t\t\tres=rule.action"
            code_callbacks+="\n\t\t\t\tbreak"
            code_callbacks+="\n\t\tif not res:"
            code_callbacks+="\n\t\t\tio.info('Packet dropped by firewall : '+packet.__repr__())"
            code_callbacks+="\n\t\treturn res\n\n"

    code_ble_tables=""
    code_gatt_filter=""

    while lines!=[]:
        if lines[0]=="BLE_TABLES":
            if code_ble_tables:
                raise IncorrectBLETableError("Several BLE_TABLES contexts in rule file")
            lines,code_ble_tables=parse_ble_tables(lines[1:])

        elif lines[0]=="GATT_FILTER":
            if code_gatt_filter:
                raise IncorrectBLETableError("Several GATT_FILTER contexts in rule file")
            lines,code_gatt_filter=parse_gatt_filter(lines[1:])

        else:
            raise IncorrectBLETableError("Non-empty line outside of contexts; please use // for comments")

    
    out_file_handle, out_file_path = tempfile.mkstemp(suffix=".py")
    os.close(out_file_handle)
    out_file_name=out_file_path.split("/")[-1][:-3]

    code=""
    
    with open("mirage/libs/fw_utils/template_scenario.py") as f:
        code=f.read().format(out_file_name, rules_dict, code_callbacks, code_ble_tables,code_gatt_filter)

    with open(out_file_path,"w") as f:
        f.write(code)

    return out_file_path,out_file_name
