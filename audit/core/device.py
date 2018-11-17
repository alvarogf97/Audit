import platform
import psutil
from audit.core.connection import Connection


# retrieve_device_information send hardware information
def retrieve_device_information(connection : Connection):
    information = ""
    information += "#"*49+"\n\n"
    information += "             SYSTEM INFORMATION\n\n"
    information += "Platform: --> " + platform.platform() + "\n"
    information += "System users: --> " + str([x.name for x in psutil.users()]) + "\n"
    information += "\n" + "#"*49+"\n\n"
    information += "             CPU INFORMATION\n\n"
    information += "CPU: --> " + platform.processor() + "\n"
    information += "Architecture: --> " + platform.machine() + "\n"
    information += "Total cores: --> " + str(psutil.cpu_count(logical=False)) + "\n"
    information += "Total threads: --> " + str(psutil.cpu_count(logical=True)) + "\n"
    total_processor_usage = psutil.cpu_percent(interval=1)
    information += "Total usage --> " + str(total_processor_usage) + "%" + "\n"
    processor_usage = psutil.cpu_percent(interval=1, percpu=True)
    for x in range(0,len(processor_usage)):
        information += "     CPU#"+str(x)+" --> " + str(processor_usage[x]) +"%" + "\n"
    mem = psutil.virtual_memory()
    information += "\n" + "#"*49+"\n\n"
    information += "             VIRTUAL MEMORY INFORMATION\n\n"
    information += "Total: --> " + str(mem.total*1e-6) + " Mb" + "\n"
    information += "Available: --> " + str(mem.available*1e-6) + " Mb" + "\n"
    information += "Used: --> " + str(mem.used*1e-6) + " Mb" + "\n"
    information += "Usage percent: --> " + str(mem.percent) + "%" + "\n"
    information += "\n" + "#"*49+"\n\n"
    information += "             DISKS MEMORY INFORMATION\n\n"
    for disk in psutil.disk_partitions(all=False):
        information += "device --> " + disk.device + "\n"
        information += "     mountpoint: --> " + disk.mountpoint + "\n"
        information += "     format: --> " + disk.fstype + "\n"
        information += "     features: --> " + disk.opts + "\n"
        disk_usage = psutil.disk_usage(disk.mountpoint)
        information += "     total: --> " + str(disk_usage.total*1e-6) + "Mb" + "\n"
        information += "     used: --> " + str(disk_usage.used*1e-6) + "Mb" + "\n"
        information += "     free: --> " + str(disk_usage.free*1e-6) + "Mb" + "\n"
        information += "     Usage percent: --> " + str(disk_usage.percent) + "%" + "\n"
    information += "\n" + "#"*49+"\n\n"
    battery = psutil.sensors_battery()
    if battery:
        information += "             BATTERY INFORMATION\n\n"
        information += "     Percent: --> " + str(battery.percent) + "%" + "\n"
        information += "     Time to left: --> " + str(battery.secsleft) + "\n"
        information += "     Power plugged: --> " + str(battery.power_plugged) + "\n"
    connection.send_msg(information)
