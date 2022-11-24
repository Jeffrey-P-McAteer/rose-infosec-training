
# Std lib utilities
import psutil
import code
import sys
import readline

# Our helper
from libhelper import importinate

# 3rdparty code
pyshark = importinate('pyshark')


# Utilities

def input_with_prefill(prompt, text):
    def hook():
        readline.insert_text(text)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result



# Grab all wireless interfaces
wireless_ifaces = []
for addr_name, addr in psutil.net_if_addrs().items():
  if sys.platform.startswith('win'):
    wireless_ifaces.append(addr_name)
  else:
    # Unix naming conventions
    if 'wlan' in addr_name:
      wireless_ifaces.append(addr_name)

print(f'Detected {len(wireless_ifaces)} interfaces:')
for i, interface in enumerate(wireless_ifaces):
  print(f' - {interface}')

interface_name = wireless_ifaces[0] if len(wireless_ifaces) > 0 else 'Error: no interfaces!' # str(input('Which interface would you like to capture? '))
print(f'Enter an interface name:')
interface_name = input_with_prefill('> ', interface_name).strip()

bpf_filter = 'tcp and port 80'
print(f'Enter a packet filter:')
bpf_filter = input_with_prefill('> ', bpf_filter).strip()

capture_seconds = 20
print(f'Capturing for {capture_seconds} seconds...')
capture = pyshark.LiveCapture(
  interface=interface_name,
  bpf_filter=bpf_filter,
)
capture.sniff(timeout=capture_seconds)

print(f'''

Interact with the variable `capture` to see what traffic was recorded from {interface_name}!

''')

variables = locals()
variables.update(globals())
code.interact(local=variables)

