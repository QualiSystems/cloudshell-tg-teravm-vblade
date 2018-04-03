from cloudshell.devices.standards.traffic.virtual.blade.configuration_attributes_structure import TrafficGeneratorVBladeResource


class TeraVMTrafficGeneratorVBladeResource(TrafficGeneratorVBladeResource):
    @property
    def tvm_comms_network(self):
        """TeraVM Comms Network Name

        :rtype: str
        """
        return self.attributes.get("{}TVM Comms Network".format(self.namespace_prefix), None)

    @property
    def tvm_mgmt_network(self):
        """TeraVM MGMT Network Name

        :rtype: str
        """
        return self.attributes.get("{}TVM MGMT Network".format(self.namespace_prefix), None)
