from audit.core.connection import Connection
from audit.core.firewall_manager import FirewallManager


class LinuxFirewallManager(FirewallManager):

    def add_rule(self, connection: Connection):
        pass

    def remove_rule(self, connection: Connection):
        pass

    def get_rules(self, connection: Connection):
        pass

    def export_firewall(self, connection: Connection):
        pass

    def import_firewall(self, connection: Connection):
        pass

    def disable(self, connection: Connection):
        pass

    def enable(self, connection: Connection):
        pass
