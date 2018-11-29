import os
from abc import abstractmethod
from audit.core.environment import Environment


class FirewallManager:

    @abstractmethod
    def firewall_descriptor(self):
        pass

    @abstractmethod
    def add_chain(self, args):
        pass

    @abstractmethod
    def remove_chain(self, args):
        pass

    @abstractmethod
    def add_rule(self, args):
        pass

    @abstractmethod
    def remove_rule(self, args):
        pass

    @abstractmethod
    def get_rules(self):
        pass

    @abstractmethod
    def export_firewall(self):
        pass

    @abstractmethod
    def import_firewall(self, args):
        pass

    @abstractmethod
    def disable(self):
        pass

    @abstractmethod
    def enable(self):
        pass

    def execute_firewall_action(self, command: str, args):
        if command.startswith("firewall add rule"):
            return self.add_rule(args)
        elif command.startswith("firewall remove rule"):
            return self.remove_rule(args)
        elif command.startswith("firewall get rules"):
            return self.get_rules()
        elif command.startswith("firewall export"):
            return self.export_firewall()
        elif command.startswith("firewall import"):
            return self.import_firewall(args)
        elif command.startswith("firewall disable"):
            return self.disable()
        elif command.startswith("firewall enable"):
            return self.enable()
        elif command.startswith("firewall descriptor"):
            return self.firewall_descriptor()
        elif command.startswith("firewall add chain "):
            return self.add_chain(args)
        elif command.startswith("firewall remove chain"):
            return self.remove_chain(args)
        else:
            result = dict()
            result["status"] = False
            result["data"] = "unavailable operation"

    @staticmethod
    def get_firewall_files():
        result = dict()
        result["status"] = True
        result["data"] = [f for f in os.listdir(Environment().path_firewall_resources)
                          if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]
        return result
