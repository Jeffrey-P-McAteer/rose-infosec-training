
# This script pretends to be a web browser looking through unencrypted
# websites. We use our own DNS client instead of the operating systems
# to make sure unencrypted DNS packets are also leaked to the network.

import time

from libhelper import importinate # Our helper code

dns = importinate('dns', 'dnspython')
import dns.resolver

# Note: Dnspython can do simple DNSSEC signature validation, but currently has no facilities for signing. In order to use DNSSEC functions, you must have python cryptography installed.
#       https://dnspython.readthedocs.io/en/latest/dnssec.html
our_dns_resolver = dns.resolver.Resolver()
our_dns_resolver.nameservers = [
  '8.8.8.8' # Google
]

while True:
  time.sleep(1)

  print('Making DNS requests...')

  print(f'our_dns_resolver.resolve("example.org", "A") = {our_dns_resolver.resolve("example.org", "A").response}')
  print(f'our_dns_resolver.resolve("example.org", "AAAA") = {our_dns_resolver.resolve("example.org", "AAAA").response}')





