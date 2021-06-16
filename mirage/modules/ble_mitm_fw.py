from mirage.libs import io,utils,ble,fw
from mirage.core import module
import os
import tempfile
import imp

class ble_mitm_fw(module.WirelessModule):
	def init(self):
		self.technology = "ble"
		self.type = "defense"
		self.description = "Man-in-the-Middle firewall module for Bluetooth Low Energy"
		self.args = {
				"INTERFACE1":"hci0", # must allow to change BD Address
				"INTERFACE2":"hci1",
				"TARGET":"FC:58:FA:A1:26:6B",
				"CONNECTION_TYPE":"public",
				"SLAVE_SPOOFING":"yes",
				"MASTER_SPOOFING":"yes",
				"ADVERTISING_STRATEGY":"preconnect", # "preconnect" (btlejuice) or "flood" (gattacker)
				"SHOW_SCANNING":"yes",
				"FW_RULES":"",
				"LTK":""
		}
		self.mitm_module=None


	def run(self):
		import mirage.scenarios as scenarios

		rules_file = self.args["FW_RULES"]

		scenario_path=None
		
		if not rules_file:
			io.fail("No firewall rules provided")
			return self.nok()

		if not os.path.isfile(rules_file):
			io.file("{} : file not found".format(rules_file))
			return self.nok()

		try:

			with open(rules_file) as f:
				rules_content = f.read()

			scenario_path,scenario_name = fw.parse_rules(rules_content)

			scenarios.__scenarios__[scenario_name]=imp.load_source(scenario_name,scenario_path)

			self.mitm_module = utils.loadModule("ble_mitm")

			mitm_args=self.args
			del mitm_args["FW_RULES"]
			mitm_args["SCENARIO"]=scenario_name

			self.mitm_module.args=mitm_args

			out=self.mitm_module.execute()

		except KeyboardInterrupt:
			out=self.ok()

		except:
			import traceback
			io.fail("Something went wrong : ")
			traceback.print_exc()
			out=self.nok()

		if scenario_path:
			os.remove(scenario_path)

		return out
