# Man-in-The-Middle firewall additions

You will find here a Proof-of-Concept implementation of a basic Man-in-The-Middle Bluetooth Low Energy firewall, based on the original Mirage framework.

## What was added in this repository

We added a firewall-specific library, which you can find [here](mirage/libs/fw_utils), along with a new module [ble\_mitm\_fw](mirage/modules/ble_mitm_fw.py) exploiting it to set up a BLE firewall.

This new module generates a custom scenario based on a configuration file as the one given [here](sp_tables.txt), then calls the standard [ble\_mitm](mirage/modules/ble_mitm.py) module to activate the firewall.

The available arguments for this new module are the same as the base MiTM module, the only difference being the **SCENARIO** parameter was replaced by **FW_RULES**, corresponding to the path to the configuration file.

## What is not possible yet

This Proof-of-Concept is a work in progress, and some functionalities are not available:

* **multiple connections management** : as of now in Mirage, each slave is to be replaced by a single BLE dongle spoofing its address, and not supporting multiple connections at the same time, while a master not needing spoofing can be managed along other similar masters on a single dongle. A possible workaround would be to replace the slave management by the use of Software Defined Radios simulating multiple slaves with different addresses at a time, but SDRs are not yet integrated in the main framework.
* **GATT server updates on the slave** : a BLE Slave may update its server's structure, which makes the former handle translations obsolete. Adding support for updates of the server's structure is a work in progress.

## How to configure the firewall

The firewall generates a custom scenario from a configuration file, that may contain one or both of the following sections:

### BLE\_TABLES

This section allows to allow or deny BLE packets matching specified rules, packets not matching any falling under a default rule, which **must** be added in the section.

The section consists of two lines `BLE_TABLES` and `END BLE_TABLES` delimiting the corresponding rules.

The mandatory default rule is to be specified by adding a line `default <allow|deny>` among the rules of this section.

Other rules are lines specified as follows:

```
action <allow|deny> type <Mirage BLE packet class> [handle <hex>] [value <hex>] [direction <master|slave>] [src <BD address>] [dst <BD address>]
```

Valid Mirage BLE packet classes can be found in [the Mirage documentation](https://homepages.laas.fr/rcayre/mirage-documentation/blestack.html#bluetooth-low-energy-packets). You can also find more information on the different parameters of this rule in the `BLETablesRule` class in [this file](mirage/libs/fw_utils/firewall_rules.py).


### GATT\_FILTER

This section allows to hide specific Services or Characteristics of the Slave's GATT server from the master device.

Similarly to the previous one, this section is delimited by two lines `GATT_FILTER` and `END GATT_FILTER`.

The rules are lines specified as follows :

```
entity GATT type <Service|Characteristic> uuid <UUID>
```

### Comments

If you need to, you can add comments in the file with "//"
