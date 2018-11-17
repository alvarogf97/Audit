import ifaddr


def get_adapters():
    res = ""
    adapters = dict()
    item = 0
    for adapter in ifaddr.get_adapters():
        res += ("     " + str(item) + ": " + adapter.ips[0].nice_name + "\n")
        adapters[item] = adapter.name.decode("utf-8")
        item += 1
    return res, adapters