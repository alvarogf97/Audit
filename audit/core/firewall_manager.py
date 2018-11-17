from abc import abstractmethod


class FirewallManager:

    @abstractmethod
    def add_rule(self): pass

    @abstractmethod
    def remove_rule(self): pass

    @abstractmethod
    def get_rules(self): pass

    @abstractmethod
    def export_firewall(self): pass

    @abstractmethod
    def import_firewall(self): pass

    @abstractmethod
    def disable(self): pass

    @abstractmethod
    def enable(self): pass

    @abstractmethod
    def reset_to_default(self): pass
