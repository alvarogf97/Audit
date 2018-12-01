import platform
import psutil


# device_info get hardware information
def device_info():
    result = dict()
    result["status"] = True

    result["data"] = dict()
    result["data"]["system"] = dict()
    result["data"]["system"]["platform"] = platform.platform()
    result["data"]["system"]["system users"] = [x.name for x in psutil.users()]

    result["data"]["cpu"] = dict()
    result["data"]["cpu"]["processor"] = platform.processor()
    result["data"]["cpu"]["architecture"] = platform.machine()
    result["data"]["cpu"]["cores"] = str(psutil.cpu_count(logical=False))
    result["data"]["cpu"]["threads"] = str(psutil.cpu_count(logical=True))
    total_processor_usage = psutil.cpu_percent(interval=1)
    result["data"]["cpu"]["usage"] = dict()
    result["data"]["cpu"]["usage"]["total"] = str(total_processor_usage) + "%"
    processor_usage = psutil.cpu_percent(interval=1, percpu=True)
    for x in range(0, len(processor_usage)):
        index = "CPU#"+str(x)
        result["data"]["cpu"]["usage"][index] = str(processor_usage[x]) + "%"

    mem = psutil.virtual_memory()
    result["data"]["virtual memory"] = dict()
    result["data"]["virtual memory"]["total"] = str(mem.total*1e-6) + " Mb"
    result["data"]["virtual memory"]["available"] = str(mem.available*1e-6) + " Mb"
    result["data"]["virtual memory"]["used"] = str(mem.used*1e-6) + " Mb"
    result["data"]["virtual memory"]["used percent"] = str(mem.percent) + "%"

    result["data"]["disks"] = []
    for disk in psutil.disk_partitions(all=False):
        disk_info = dict()
        disk_info[disk.device] = dict()
        disk_info[disk.device]["mountpoint"] = disk.mountpoint
        disk_info[disk.device]["format"] = disk.fstype
        disk_info[disk.device]["features"] = disk.opts
        disk_usage = psutil.disk_usage(disk.mountpoint)
        disk_info[disk.device]["total"] = str(disk_usage.total*1e-6) + "Mb"
        disk_info[disk.device]["used"] = str(disk_usage.used*1e-6) + "Mb"
        disk_info[disk.device]["free"] = str(disk_usage.free*1e-6) + "Mb"
        disk_info[disk.device]["used percent"] = str(disk_usage.percent) + "%"
        result["data"]["disks"].append(disk_info)

    battery = psutil.sensors_battery()
    if battery:
        result["data"]["battery"] = dict()
        result["data"]["battery"]["percent"] = str(battery.percent)
        result["data"]["battery"]["remaining time"] = str(battery.secsleft)
        result["data"]["battery"]["power"] = str(battery.power_plugged)

    return result
