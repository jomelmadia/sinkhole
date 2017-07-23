# sinkhole
Scripts for filtering and reporting on a local host file based DNS sinkhole, two crude sinkhole implementations in python inspired by
[IPTrap](https://github.com/jedisct1/iptrap)

## Credits
Firstly to [Steven Black](https://github.com/StevenBlack) for the curated host file, that's the hard bit!

## What's here?
A couple of cron scripts, and a config file, in LSB layout, that should work on many *nix-like systems.

Script 1 (x1-report-hosts-blocked), aggregates some daily stats from your DNS server log and relies on cron to email out.
It can also apply a filter to lower the noise from many, many ad servers blocks, leaving you with the scary stuff.

Script 2 (x2-update-hosts-blocked), pulls the curated list from Steven, applies a host exclusion filter, duplicates for IPv4 and IPv6,
drops the results in /var/tmp and restarts dnsmasq to update blocked hosts.

The config (etc/default/sinkhole) contains the host exclusion list, chosen IP addresses to respond with and the report filter list.

pysink.py: Scapy based sinkhole script (unusably slow)

raw.py: badly named, raw socket based sinkhole (usably fast)

That's it!
