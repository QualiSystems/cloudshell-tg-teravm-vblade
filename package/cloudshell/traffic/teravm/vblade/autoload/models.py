from cloudshell.devices.standards.traffic.virtual.autoload_structure import Chassis
from cloudshell.devices.standards.traffic.virtual.autoload_structure import Module
from cloudshell.devices.standards.traffic.virtual.autoload_structure import Port


class TeraVMChassis(Chassis):
    RESOURCE_MODEL = "TeraVM Chassis"


class TeraVMModule(Module):
    RESOURCE_MODEL = "TeraVM Virtual Traffic Generator Module"


class TeraVMPort(Port):
    RESOURCE_MODEL = "TeraVM Virtual Traffic Generator Port"
