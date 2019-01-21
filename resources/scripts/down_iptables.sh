#!/bin/bash

# set to true if it is CentOS / RHEL / Fedora box
RHEL=false
IPT=/sbin/iptables
IPT6=/sbin/ip6tables

if [ "$RHEL" == "true" ];
then
      # reset firewall using redhat script
    /etc/init.d/iptables stop
    /etc/init.d/ip6tables stop
else
    # for all other Linux distro use following rules to reset firewall
    ### reset ipv4 iptales ###
    $IPT -F
    $IPT -X
    $IPT -Z
    for table in $(</proc/net/ip_tables_names)
    do
        $IPT -t $table -F
        $IPT -t $table -X
        $IPT -t $table -Z
    done
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    ### reset ipv6 iptales ###
    $IPT6 -F
    $IPT6 -X
    $IPT6 -Z
    for table in $(</proc/net/ip6_tables_names)
    do
        $IPT6 -t $table -F
        $IPT6 -t $table -X
        $IPT6 -t $table -Z
    done
    $IPT6 -P INPUT ACCEPT
    $IPT6 -P OUTPUT ACCEPT
    $IPT6 -P FORWARD ACCEPT
fi
