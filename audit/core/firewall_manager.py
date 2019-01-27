import os
from abc import abstractmethod

from audit.core.environment import Environment


class FirewallManager:

    def __init__(self):
        self.rules = None

    @abstractmethod
    def firewall_descriptor(self):
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
    def export_firewall(self, args):
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

    @abstractmethod
    def status(self):
        pass

    @abstractmethod
    def parse_rules(self, string):
        pass

    @abstractmethod
    def is_compatible(self):
        pass

    @abstractmethod
    def parse_status(self, string):
        pass

    @abstractmethod
    def execute_firewall_action(self, command: str, args):
        pass

    @staticmethod
    def check_file(filename):
        return filename in [f for f in os.listdir(Environment().path_firewall_resources)
                            if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]

    @staticmethod
    def get_firewall_files():
        result = dict()
        result["status"] = True
        result["data"] = [f for f in os.listdir(Environment().path_firewall_resources)
                          if os.path.isfile(os.path.join(Environment().path_firewall_resources, f))]
        return result


class Rule:

    def __init__(self, number, name, **kwargs):
        self.number = number
        self.kwargs = kwargs
        self.name = name

    def to_json(self):
        result = dict()
        result["number"] = self.number
        result["name"] = self.name
        result.update(self.kwargs)
        return result

    @staticmethod
    def list_to_json(rule_list):
        result = []
        for rule in rule_list:
            result.append(rule.to_json())
        return result
