import json
import itertools

from cloudshell.api.cloudshell_api import SetConnectorRequest, AttributeNameValue
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


ATTR_REQUESTED_VNIC_NAME = "Requested vNIC Name"
ATTR_REQUESTED_SOURCE_VNIC = "Requested Source vNIC Name"
ATTR_REQUESTED_TARGET_VNIC = "Requested Target vNIC Name"
MODEL_PORT = "TeraVM Virtual Traffic Generator Port"
VCENTER_RESOURCE_USER_ATTR = "User"
VCENTER_RESOURCE_PASSWORD_ATTR = "Password"


class ConnectorData(object):
    def __init__(self, direction, free_ports, source=None, target=None, source_vnic=None, target_vnic=None):
        """

        :param str direction: connector direction
        :param dict[str, Port] free_ports: free resource ports
        :param str source: source port name
        :param str target: target port name
        :param str source_vnic: source vNIC adapter number
        :param str target_vnic: target vNIC adapter number
        """
        self.direction = direction
        self.source_vnic = source_vnic
        self.target_vnic = target_vnic
        self._source = source
        self._target = target
        self._free_ports = free_ports

    def _get_free_port(self):
        """Get the last port from the free ports dictionary

        :return:
        """
        try:
            vnic_id = self._free_ports.keys()[-1]
        except IndexError:
            raise Exception("No free ports left on the resource")

        return self._free_ports.pop(vnic_id)

    @property
    def source(self):
        if not self._source:
            self._source = self._get_free_port().Name
        return self._source

    @property
    def target(self):
        if not self._target:
            self._target = self._get_free_port().Name
        return self._target


class TeraVMVbladeDriver(ResourceDriverInterface):
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

    def _create_connector_data(self, is_source, source_vnic, target_vnic, ports, connector):
        """

        :param is_source:
        :param source_vnic:
        :param target_vnic:
        :param ports:
        :param connector:
        :rtype: ConnectorData
        """
        source = None
        target = None

        if is_source:
            target = connector.target
            if source_vnic:
                port = ports.pop(source_vnic)
                source = port.Name
        else:
            source = connector.source
            if target_vnic:
                port = ports.pop(target_vnic)
                target = port.Name

        return ConnectorData(direction=connector.direction,
                             free_ports=ports,
                             source=source,
                             target=target,
                             source_vnic=source_vnic,
                             target_vnic=target_vnic)

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

            if not context.connectors:
                return "Success"

            api = get_api(context)
            resource = api.GetResourceDetails(resource_name)

            new_connectors_data = []
            to_disconnect = []

            ports = self._get_ports(resource)
            logger.info("Found ports on the resource {}".format(ports))

            for connector in connectors:
                source_remap_vnics = connector.attributes.get(ATTR_REQUESTED_SOURCE_VNIC, "").split(",")
                target_remap_vnics = connector.attributes.get(ATTR_REQUESTED_TARGET_VNIC, "").split(",")

                source = connector.source
                target = connector.target

                # remove old connector
                to_disconnect.extend([source, target])

                if resource_name in connector.source.split("/"):
                    is_source = True
                else:
                    is_source = False

                for source_vnic, target_vnic in itertools.izip_longest(source_remap_vnics, target_remap_vnics):
                    new_connector_data = self._create_connector_data(is_source=is_source,
                                                                     source_vnic=source_vnic,
                                                                     target_vnic=target_vnic,
                                                                     ports=ports,
                                                                     connector=connector)
                    new_connectors_data.append(new_connector_data)

            api.RemoveConnectorsFromReservation(reservation_id, to_disconnect)

            new_connectors = []
            for connector_data in new_connectors_data:
                conn = SetConnectorRequest(SourceResourceFullName=connector_data.source,
                                           TargetResourceFullName=connector_data.target,
                                           Direction=connector_data.direction,
                                           Alias=None)
                new_connectors.append(conn)

            api.SetConnectorsInReservation(reservation_id, new_connectors)

            for connector_data in new_connectors_data:
                connector_attrs = []

                if connector_data.source_vnic:
                    connector_attr = AttributeNameValue(Name=ATTR_REQUESTED_SOURCE_VNIC,
                                                        Value=connector_data.source_vnic)
                    connector_attrs.append(connector_attr)

                if connector_data.target_vnic:
                    connector_attr = AttributeNameValue(Name=ATTR_REQUESTED_TARGET_VNIC,
                                                        Value=connector_data.target_vnic)
                    connector_attrs.append(connector_attr)

                if connector_attrs:
                    api.SetConnectorAttributes(reservationId=reservation_id,
                                               sourceResourceFullName=connector_data.source,
                                               targetResourceFullName=connector_data.target,
                                               attributeRequests=connector_attrs)

            return "Success"

    @staticmethod
    def _get_ports(resource):
        ports = {}
        for port in resource.ChildResources:
            if port.ResourceModelName == MODEL_PORT:
                vnic_name = TeraVMVbladeDriver._get_resource_attribute_value(resource=port,
                                                                             attribute_name=ATTR_REQUESTED_VNIC_NAME)
                ports[vnic_name] = port

        return ports


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
