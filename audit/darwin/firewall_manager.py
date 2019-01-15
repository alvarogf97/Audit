from audit.core.firewall_manager import FirewallManager


class DarwinFirewallManager(FirewallManager):

    def __init__(self):
        super().__init__()

    def firewall_descriptor(self):
        pass

    def add_chain(self, args):
        pass

    def remove_chain(self, args):
        pass

    def add_rule(self, args):
        pass

    def remove_rule(self, args):
        pass

    def get_rules(self):
        pass

    def export_firewall(self, args):
        pass

    def import_firewall(self, args):
        pass

    def disable(self):
        pass

    def enable(self):
        pass

    def status(self):
        pass

    def parse_rules(self, string):
        pass

    def is_compatible(self):
        return True