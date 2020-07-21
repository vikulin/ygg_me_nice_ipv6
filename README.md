# ygg_me_nice_ipv6
This go project generates nice ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd , etc

example:
5 is a number of matching bytes and 1000000000 attempts

>ygg_nice_ipv6.exe 5 1000000000
>found CPU cores: 12

>999999996 / 1000000000 [-------------------------------------------------------------------------->] 100.00% 126542 p/s

This command will find single match for c0fe in IPv6 address:

>ygg_nice_ipv6.exe 1 1000000000 c0fe

This command will find single match for :: in IPv6 address:

>ygg_nice_ipv6.exe 1 1000000000 00000000
