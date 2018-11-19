from abc import abstractmethod

from audit.core.connection import Connection


class FirewallManager:

    @abstractmethod
    def start(self, connection: Connection): pass

    @abstractmethod
    def add_rule(self, connection: Connection): pass

    @abstractmethod
    def remove_rule(self, connection: Connection): pass

    @abstractmethod
    def get_rules(self, connection: Connection): pass

    @abstractmethod
    def export_firewall(self, connection: Connection): pass

    @abstractmethod
    def import_firewall(self, connection: Connection): pass

    @abstractmethod
    def disable(self, connection: Connection): pass

    @abstractmethod
    def enable(self, connection: Connection): pass
