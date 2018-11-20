import vulners
from collections import namedtuple
from ctypes import byref, create_unicode_buffer, windll
from ctypes.wintypes import DWORD
from itertools import count
from typing import List, Dict

from audit.core.environment import Environment
from audit.core.packet_manager import PacketManager, Package, Vulnerability


class WindowsPacketManager(PacketManager):
    """Product subclass"""
    UID_BUFFER_SIZE = 39
    PROPERTY_BUFFER_SIZE = 256
    ERROR_MORE_DATA = 234
    ERROR_INVALID_PARAMETER = 87
    ERROR_SUCCESS = 0
    ERROR_NO_MORE_ITEMS = 259
    ERROR_UNKNOWN_PRODUCT = 1605

    PRODUCT_PROPERTIES = [u'Language',
                          u'ProductName',
                          u'PackageCode',
                          u'Transforms',
                          u'AssignmentType',
                          u'PackageName',
                          u'InstalledProductName',
                          u'VersionString',
                          u'RegCompany',
                          u'RegOwner',
                          u'ProductID',
                          u'ProductIcon',
                          u'InstallLocation',
                          u'InstallSource',
                          u'InstallDate',
                          u'Publisher',
                          u'LocalPackage',
                          u'HelpLink',
                          u'HelpTelephone',
                          u'URLInfoAbout',
                          u'URLUpdateInfo', ]

    Product = namedtuple('Product', PRODUCT_PROPERTIES)

    def __init__(self, path_download_files: str):
        applications = {
            "pcap":
                ("https://nmap.org/npcap/dist/npcap-0.99-r7.exe",
                 "npcap.exe",
                 ["npcap.exe"])
        }
        dependencies = dict()
        super().__init__(path_download_files, applications, dependencies)

    def get_property_for_product(self, product, property, buf_size=PROPERTY_BUFFER_SIZE):
        """ Returns the value of a given property from a product."""
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(product, property, property_buffer,
                                               byref(size))
        if result == self.ERROR_MORE_DATA:
            return self.get_property_for_product(product, property,
                                                 2 * buf_size)
        elif result == self.ERROR_SUCCESS:
            return property_buffer.value
        else:
            return ''

    def populate_product(self, uid):
        """Return a Product with the different present data."""
        properties = []
        for property in self.PRODUCT_PROPERTIES:
            properties.append(self.get_property_for_product(uid, property))
        return self.Product(*properties)

    def get_installed_products_uids(self):
        """Returns a list with all the different uid of the installed apps."""
        # enum will return an error code according to the result of the app
        products = []
        for i in count(0):
            uid_buffer = create_unicode_buffer(self.UID_BUFFER_SIZE)
            result = windll.msi.MsiEnumProductsW(i, uid_buffer)
            if result == self.ERROR_NO_MORE_ITEMS:
                # done iterating over the collection
                break
            products.append(uid_buffer.value)
        return products

    def is_product_installed_uid(self, uid):
        buf_size = 256
        uid_buffer = create_unicode_buffer(uid)
        property = u'VersionString'
        property_buffer = create_unicode_buffer(buf_size)
        size = DWORD(buf_size)
        result = windll.msi.MsiGetProductInfoW(uid_buffer, property, property_buffer,
                                               byref(size))
        if result == self.ERROR_UNKNOWN_PRODUCT:
            return False
        else:
            return True

    def get_installed_packets(self) -> List[Package]:
        packages = []
        for p_uid in self.get_installed_products_uids():
            product = self.populate_product(p_uid)
            if product.ProductName != "" and product.VersionString != "":
                name = product.ProductName.split(" ")
                if len(name) > 1:
                    name = " ".join(name[0:2])
                else:
                    name = product.ProductName
                p = Package(name, product.VersionString)
                if p not in packages:
                    packages.append(p)
        return packages

    def get_vulnerabilities(self) -> Dict[Package, List[Vulnerability]]:
        packages = self.get_installed_packets()
        packages.append(Package(Environment().os, Environment().system_version.split(".")[0]))
        vulnerabilities = dict()
        for packet in packages:
            vulnerabilities[packet] = []
            vulners_api = vulners.Vulners(api_key=Environment().vulners_api_key)
            search = None
            while search is None:
                try:
                    search = vulners_api.softwareVulnerabilities(packet.name, packet.version.split(".")[0], 3)
                except:
                    search = None
            search = [search.get(key) for key in search if key not in ['info', 'blog', 'bugbounty']]
            for type_vulner in search:
                for vulner in type_vulner:
                    v = Vulnerability(title=vulner.get("title"),
                                      score=vulner.get("cvss").get("score"),
                                      href=vulner.get("href"),
                                      published=vulner.get("published"),
                                      last_seen=vulner.get("lastseen"),
                                      reporter=vulner.get("reporter"),
                                      cumulative_fix=vulner.get("cumulative_fix"))
                    vulnerabilities[packet].append(v)
        return vulnerabilities
