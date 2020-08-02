# Yggdrasil nice IPv6 generator
This go project generates nice Yggdrasil ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd , etc

Examples:
This command will find single match for c0fe in IPv6 address:

>ygg_nice_ipv6.exe 1 1000000000 c0fe


This command will find single match for :: in IPv6 address:

>ygg_nice_ipv6.exe 1 1000000000 00000000

This command will find beautiful address with 4 mirrored address blocks.
For example: 204:bdbd:44b5:9191:7e7e:1635:e3e3:3504

>ygg_nice_ipv6.exe 4 1000000
