from abc import abstractmethod

from audit.core.connection import Connection


class FirewallManager:

    def start(self, connection: Connection):
        options = "1    add rule\n" \
                + "2    remove rule\n" \
                + "3    get rules\n" \
                + "4    export firewall settings\n" \
                + "5    import firewall settings\n" \
                + "6    disable firewall\n" \
                + "7    enable firewall\n" \
                + "8    exit"
        connection.send_msg(options)
        option = connection.recv_msg()
        while option != "8":
                if(option == "1"):
                    self.add_rule(connection)
                elif(option == "2"):
                    self.remove_rule(connection)
                elif (option == "3"):
                    self.get_rules(connection)
                elif (option == "4"):
                    self.export_firewall(connection)
                elif (option == "5"):
                    self.import_firewall(connection)
                elif (option == "6"):
                    self.disable(connection)
                elif (option == "7"):
                    self.enable(connection)
                option = connection.recv_msg()


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
