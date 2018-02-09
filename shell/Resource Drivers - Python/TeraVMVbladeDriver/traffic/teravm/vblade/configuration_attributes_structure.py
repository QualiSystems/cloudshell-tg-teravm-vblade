class TrafficGeneratorVBladeResource(object):
    def __init__(self, address=None, family=None, shell_name=None, fullname=None, name=None, attributes=None):
        """

        :param str address: IP address of the resource
        :param str family: resource family
        :param str shell_name: shell name
        :param str fullname: full name of the resource
        :param str name: name of the resource
        :param dict[str, str] attributes: attributes of the resource
        """
        self.address = address
        self.family = family
        self.shell_name = shell_name
        self.fullname = fullname
        self.name = name
        self.attributes = attributes or {}

        if shell_name:
            self.namespace_prefix = "{}.".format(self.shell_name)
        else:
            self.namespace_prefix = ""

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

    @classmethod
    def from_context(cls, context, shell_name=None):
        """Create an instance of TrafficGeneratorVBladeResource from the given context

        :param cloudshell.shell.core.driver_context.ResourceCommandContext context:
        :param str shell_name: shell Name
        :rtype: TrafficGeneratorVBladeResource
        """
        return cls(family=context.resource.family,
                   shell_name=shell_name,
                   fullname=context.resource.fullname,
                   attributes=dict(context.resource.attributes),
                   name=context.resource.name)
