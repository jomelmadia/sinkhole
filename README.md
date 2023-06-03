# sinkhole
Scripts for filtering and reporting on a local host file based DNS sinkhole, two crude sinkhole implementations in python inspired by
[IPTrap](https://github.com/jedisct1/iptrap)

## Credits
Firstly to [Steven Black](https://github.com/StevenBlack) for the curated host file, that's the hard bit!

## What's here?
A couple of cron scripts, and a config file, in LSB layout, that should work on many *nix-like systems.

Script 1 (x1-report-hosts-blocked), aggregates some daily stats from your DNS server log and relies on cron to email out. This is now a python implementation that shows only new hits compared to the previous day, preserving the full list each day in `/var/cache/sinkhole/suppress.dat`. Please ensure you have created the parent directory..

Script 2 (x2-update-hosts-blocked), pulls the curated list from Steven, applies a host exclusion filter, duplicates for IPv4 and IPv6,
drops the results in /var/tmp and restarts dnsmasq to update blocked hosts.

The config (etc/default/sinkhole) contains the host exclusion list, the chosen IP addresses to respond with.

pysink.py: Scapy based sinkhole script (unusably slow)

raw.py: badly named, raw socket based sinkhole (usably fast)

## Any more info?
I blogged about it a bit [https://ashbysoft.com/wiki/Blackhole%20DNS](https://ashbysoft.com/wiki/Blackhole%20DNS)

That's it!
