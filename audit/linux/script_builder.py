from audit.core.core import shell_command

DOWN_IPTABLES_SCRIPT = "" \
                    "#!/bin/bash\n" \
                    "# set to true if it is CentOS / RHEL / Fedora box\n" \
                    "RHEL=false\n" \
                    "IPT=/sbin/iptables\n" \
                    "IPT6=/sbin/ip6tables\n" \
                    "if [ \"$RHEL\" == \"true\" ];\n" \
                    "then\n" \
                    "      # reset firewall using redhat script\n" \
                    "    /etc/init.d/iptables stop\n" \
                    "    /etc/init.d/ip6tables stop\n" \
                    "else\n" \
                    "    # for all other Linux distro use following rules to reset firewall\n" \
                    "    ### reset ipv4 iptales ###\n" \
                    "    $IPT -F\n" \
                    "    $IPT -X\n" \
                    "    $IPT -Z\n" \
                    "    for table in $(</proc/net/ip_tables_names)\n" \
                    "    do\n" \
                    "        $IPT -t $table -F\n" \
                    "        $IPT -t $table -X\n" \
                    "        $IPT -t $table -Z\n" \
                    "    done\n" \
                    "    $IPT -P INPUT ACCEPT\n" \
                    "    $IPT -P OUTPUT ACCEPT\n" \
                    "    $IPT -P FORWARD ACCEPT\n" \
                    "    ### reset ipv6 iptales ###\n" \
                    "    $IPT6 -F\n" \
                    "    $IPT6 -X\n" \
                    "    $IPT6 -Z\n" \
                    "    for table in $(</proc/net/ip6_tables_names)\n" \
                    "    do\n" \
                    "        $IPT6 -t $table -F\n" \
                    "        $IPT6 -t $table -X\n" \
                    "        $IPT6 -t $table -Z\n" \
                    "    done\n" \
                    "    $IPT6 -P INPUT ACCEPT\n" \
                    "    $IPT6 -P OUTPUT ACCEPT\n" \
                    "    $IPT6 -P FORWARD ACCEPT\n" \
                    "fi"


def generate_scripts(path_scripts):
    with open(path_scripts + "/down_iptables.sh", "w") as f:
        f.write(DOWN_IPTABLES_SCRIPT)
    shell_command("chmod +x " + path_scripts + "/down_iptables.sh")
