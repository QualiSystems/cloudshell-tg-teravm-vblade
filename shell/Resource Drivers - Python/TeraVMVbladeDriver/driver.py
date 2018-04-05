import json

from cloudshell.core.context.error_handling_context import ErrorHandlingContext
from cloudshell.devices.driver_helper import get_api
from cloudshell.devices.autoload.autoload_builder import AutoloadDetailsBuilder
from cloudshell.devices.driver_helper import get_logger_with_thread_id
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.cp.vcenter.common.vcenter.vmomi_service import pyVmomiService
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from cloudshell.traffic.teravm.vblade.configuration_attributes_structure import TeraVMTrafficGeneratorVBladeResource
from cloudshell.traffic.teravm.vblade.autoload import models
from cloudshell.traffic.virtual.resource_driver_interface import VirtualTrafficGeneratorResourceDriverInterface
from cloudshell.traffic.virtual.runners.connect_child_resources import ConnectChildResourcesRunner


MODEL_PORT = "TeraVM Virtual Traffic Generator Port"
VCENTER_RESOURCE_USER_ATTR = "User"
VCENTER_RESOURCE_PASSWORD_ATTR = "Password"


class TeraVMVbladeDriver(ResourceDriverInterface, VirtualTrafficGeneratorResourceDriverInterface):
    def __init__(self):
        """Constructor must be without arguments, it is created with reflection at run time"""
        pass

    def initialize(self, context):
        """Initialize the driver session, this function is called everytime a new instance of the driver is created.

        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    @staticmethod
    def _get_resource_attribute_value(resource, attribute_name):
        """

        :param resource cloudshell.api.cloudshell_api.ResourceInfo:
        :param str attribute_name:
        """
        for attribute in resource.ResourceAttributes:
            if attribute.Name == attribute_name:
                return attribute.Value

    def get_inventory(self, context):
        """Discovers the resource structure and attributes.

        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        logger = get_logger_with_thread_id(context)
        logger.info("Autoload")

        with ErrorHandlingContext(logger):
            cs_api = get_api(context)

            vblade_resource = TeraVMTrafficGeneratorVBladeResource.from_context(context)

            # get VM uuid of the Deployed App
            deployed_vm_resource = cs_api.GetResourceDetails(vblade_resource.fullname)
            vmuid = deployed_vm_resource.VmDetails.UID
            logger.info("Deployed TVM Module App uuid: {}".format(vmuid))

            # get vCenter name
            app_request_data = json.loads(context.resource.app_context.app_request_json)
            vcenter_name = app_request_data["deploymentService"]["cloudProviderName"]
            logger.info("vCenter shell resource name: {}".format(vcenter_name))

            vsphere = pyVmomiService(SmartConnect, Disconnect, task_waiter=None)

            # get vCenter credentials
            vcenter_resource = cs_api.GetResourceDetails(resourceFullPath=vcenter_name)
            user = self._get_resource_attribute_value(resource=vcenter_resource,
                                                      attribute_name=VCENTER_RESOURCE_USER_ATTR)

            encrypted_password = self._get_resource_attribute_value(resource=vcenter_resource,
                                                                    attribute_name=VCENTER_RESOURCE_PASSWORD_ATTR)

            password = cs_api.DecryptPassword(encrypted_password).Value

            logger.info("Connecting to the vCenter: {}".format(vcenter_name))
            si = vsphere.connect(address=vcenter_resource.Address, user=user, password=password)

            # find Deployed App VM on the vCenter
            vm = vsphere.get_vm_by_uuid(si, vmuid)

            phys_interfaces = []
            comms_mac_addr = None

            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                    if device.deviceInfo.summary.lower() == vblade_resource.tvm_comms_network.lower():
                        comms_mac_addr = device.macAddress
                    else:
                        phys_interfaces.append(device)

            if comms_mac_addr is None:
                raise Exception("Unable to find TVM Comms network with name '{}' on the device"
                                .format(vblade_resource.tvm_comms_network))

            logger.info("Found interfaces on the device: {}".format(phys_interfaces))
            module_res = models.TeraVMModule(shell_name="",
                                             name="Module {}".format(comms_mac_addr.replace(":", "-")),
                                             unique_id=hash(comms_mac_addr))

            logger.info("Updating resource address for the module to {}".format(comms_mac_addr))
            cs_api.UpdateResourceAddress(context.resource.fullname, comms_mac_addr)

            for port_number, phys_interface in enumerate(phys_interfaces, start=1):
                network_adapter_number = phys_interface.deviceInfo.label.lower().strip("network adapter ")
                unique_id = hash(phys_interface.macAddress)
                port_res = models.TeraVMPort(shell_name="",
                                             name="Port {}".format(port_number),
                                             unique_id=unique_id)

                port_res.mac_address = phys_interface.macAddress
                port_res.requested_vnic_name = network_adapter_number
                module_res.add_sub_resource(unique_id, port_res)

            return AutoloadDetailsBuilder(module_res).autoload_details()

    def cleanup(self):
        """ Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """

        pass

    def connect_child_resources(self, context):
        """

        :type context: cloudshell.shell.core.driver_context.ResourceCommandContext
        :rtype: str
        """
        logger = get_logger_with_thread_id(context)
        logger.info("Connect child resources command started")

        with ErrorHandlingContext(logger):
            resource_name = context.resource.fullname
            reservation_id = context.reservation.reservation_id
            connectors = context.connectors
            api = get_api(context)

            connect_operation = ConnectChildResourcesRunner(logger=logger,
                                                            cs_api=api)

            ports = connect_operation.get_ports(resource_name=resource_name,
                                                port_model=MODEL_PORT)

            return connect_operation.connect_child_resources(connectors=connectors,
                                                             ports=ports,
                                                             resource_name=resource_name,
                                                             reservation_id=reservation_id)

if __name__ == "__main__":
    import mock
    from cloudshell.shell.core.context import ResourceCommandContext, ResourceContextDetails, ReservationContextDetails

    address = '192.168.42.222'

    user = 'cli'
    password = 'diversifEye'
    port = 443
    scheme = "https"
    auth_key = 'h8WRxvHoWkmH8rLQz+Z/pg=='
    api_port = 8029

    context = ResourceCommandContext()
    context.resource = ResourceContextDetails()
    context.resource.name = 'dd_5915-07f0'
    context.resource.fullname = 'dd_5915-07f0'
    context.reservation = ReservationContextDetails()
    context.reservation.reservation_id = '0cc17f8c-75ba-495f-aeb5-df5f0f9a0e97'
    context.resource.attributes = {}
    context.resource.attributes['User'] = user
    context.resource.attributes['Password'] = password
    context.resource.attributes['TVM Comms Network'] = "TVM_Comms_VLAN_99"
    context.resource.attributes['TVM MGMT Network'] = "TMV_Mgmt"
    context.resource.address = address
    context.resource.app_context = mock.MagicMock(app_request_json=json.dumps(
        {
            "deploymentService": {
                "cloudProviderName": "vCenter"
            }
        }))

    context.connectivity = mock.MagicMock()
    context.connectivity.server_address = "192.168.85.20"

    dr = TeraVMVbladeDriver()
    dr.initialize(context)

    result = dr.get_inventory(context)

    for resource in result.resources:
        print resource.__dict__
