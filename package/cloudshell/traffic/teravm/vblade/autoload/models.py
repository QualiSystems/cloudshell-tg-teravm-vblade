from cloudshell.devices.standards.base import AbstractResource


class Chassis(AbstractResource):
    RESOURCE_MODEL = "TeraVM Chassis"
    RELATIVE_PATH_TEMPLATE = "CH"


class Module(AbstractResource):
    RESOURCE_MODEL = "TeraVM Virtual Traffic Generator Module"
    RELATIVE_PATH_TEMPLATE = "M"

    @property
    def device_model(self):
        """

        :return:
        """
        return self.attributes.get("Model", None)

    @device_model.setter
    def device_model(self, value):
        """

        :param value:
        :return:
        """
        self.attributes["Model"] = value


class Port(AbstractResource):
    RESOURCE_MODEL = "TeraVM Virtual Traffic Generator Port"
    RELATIVE_PATH_TEMPLATE = "P"

    @property
    def logical_name(self):
        return self.get('Logical Name', None)

    @logical_name.setter
    def logical_name(self, value):
        """

        :param value:
        :return:
        """
        self.attributes["Logical Name"] = value

    @property
    def mac_address(self):
        return self.get('MAC Address', None)

    @mac_address.setter
    def mac_address(self, value):
        """

        :param value:
        :return:
        """
        self.attributes["MAC Address"] = value
