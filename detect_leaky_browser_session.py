
# Std lib utilities
import psutil
import code
import sys
import readline
import traceback
import subprocess
import threading
import time
import random

# Our helper
from libhelper import importinate

# 3rdparty code
pyshark = importinate('pyshark')
getmac = importinate('getmac', 'get-mac')
pyric = importinate('pyric', 'PyRIC') # TODO investigate https://github.com/wifiphisher/wifiphisher ?
import pyric.pyw as pyw


# Utilities

def input_with_prefill(prompt, text):
    def hook():
        readline.insert_text(text)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result

def cmd(*parts, check=True):
  if len(parts) == 1 and isinstance(parts[0], list):
    parts = parts[0]
  print(f'CMD> {" ".join(list(parts))}')
  subprocess.run(list(parts), check=check)

# Silences errors, useful for parsing unknown data
def maybe(function):
  try:
    return function()
  except:
    return None

# Keep a list of known machines to make captures packet traces
# more human readable (eg John's iPad instead of aa:bb:cc:11:22:33 )
MAC_INFO_DICT = {
  '60:f2:62:e5:ee:94': "Jeffrey's thinkpad wlan1",
  '3c:33:00:20:48:02': "Jeffrey's thinkpad wlan1 (removable 2.4ghz card)",
  'c8:c7:50:ec:4e:11': "Primary Gateway wlan0 (serves 5ghz and 2.4ghz spectrums)", # Saw c8:c7:50:ec:4e:11 using 2.4ghz network
  '': "",
}
def enrich_mac_info(mac_addr):
  global MAC_INFO_DICT
  return MAC_INFO_DICT.get(mac_addr, mac_addr)

def enrich_ip_addr(ip_addr):
  mac_addr = ip_addr
  if ':' in ip_addr:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip6=ip_addr))
  else:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip=ip_addr))
  if mac_addr is None:
    mac_addr = ip_addr
  return enrich_mac_info(mac_addr)

# Grab all wireless interfaces
wireless_ifaces = pyw.winterfaces()
print(f'Detected {len(wireless_ifaces)} interfaces:')
for i, interface in enumerate(wireless_ifaces):
  print(f' - {interface}')

interface_name = wireless_ifaces[len(wireless_ifaces)-1] if len(wireless_ifaces) > 0 else 'Error: no interfaces!' # str(input('Which interface would you like to capture? '))
print(f'Enter an interface name to capture with:')
interface_name = input_with_prefill('> ', interface_name).strip()
interface = pyw.getcard(interface_name)
if not 'monitor' in pyw.devmodes(interface):
  print(f'Error, {interface_name} does not have monitor mode available! Modes: {pyw.devmodes(interface)}')
  sys.exit(1)

try:
  MAC_INFO_DICT[pyw.macget(interface)] = 'This machine'
except:
  pass

channels_to_tune_to = '1,2,3,4,5,6,7,8,9,10,11'
print(f'Enter a list of channels to tune between; only one channel may be listened to at a time.')
print(f'Note that channels 12, 13, and 14 require residency outside north america to avoid interference with flight radar equiptment (See https://en.wikipedia.org/wiki/List_of_WLAN_channels#2.4_GHz_(802.11b/g/n/ax) )')
channels_to_tune_to = input_with_prefill('> ', channels_to_tune_to).strip()
channels_to_tune_to = [x.strip() for x in channels_to_tune_to.split(',') if len(x.strip()) > 0]
print(f'Got {len(channels_to_tune_to)} channels: {channels_to_tune_to}')

channel_band_width = '20'
print(f'Enter the bandwidth (One of 20,40,+); for each channel this defines how much interference is accepted from neighboring channels, the higher the width the more neighbor channels will be captured at once.')
channel_band_width = input_with_prefill('> ', channel_band_width).strip()

if '20' in channel_band_width:
  channel_band_width = 'HT20'
elif '40' in channel_band_width:
  channel_band_width = 'HT40-'
else:
  channel_band_width = 'HT40+'
print(f'channel_band_width = {channel_band_width}')

bpf_filter = 'tcp and port 80'
print(f'Enter a packet filter:')
bpf_filter = input_with_prefill('> ', bpf_filter).strip()

pyw.down(interface)
pyw.modeset(interface, 'monitor')
pyw.up(interface)

seconds_between_channel_hop = 12
exit_flag = False

current_channel = channels_to_tune_to[0]

# We hop between channels every 10 seconds, or faster (2s) if
# we have >0 packets for all channels and the selected channel's
# per_channel_packet_count_d record is less than the average.
def channel_hop_t():
  global interface
  global exit_flag
  global current_channel
  global channels_to_tune_to
  global per_channel_packet_count_d

  channels_to_tune_to_i = -1

  sleep_interval_s = seconds_between_channel_hop
  
  while not exit_flag:
    
    time.sleep(sleep_interval_s)
    
    # Tune to next channel in list
    channels_to_tune_to_i += 1
    if channels_to_tune_to_i >= len(channels_to_tune_to):
      channels_to_tune_to_i = 0

    print(f'Hopping to {channels_to_tune_to[channels_to_tune_to_i]}')
    try:
      pyw.chset(interface, int(channels_to_tune_to[channels_to_tune_to_i]), channel_band_width)
      current_channel = channels_to_tune_to[channels_to_tune_to_i]
    except:
      traceback.print_exc()
      # Go back to previous channel
      channels_to_tune_to_i -= 1
      if channels_to_tune_to_i < 0:
        channels_to_tune_to_i = len(channels_to_tune_to) - 1

    # Now adjust sleep_interval_s based on what metadata we have for different channels.
    
    total_packets = sum([v for k,v in per_channel_packet_count_d.items()])
    average_packets_per_channel = total_packets / max(len(channels_to_tune_to), 1)
    average_packets_per_channel *= 0.8 # Hedge towards under-performing channels a bit more

    if per_channel_packet_count_d.get(channels_to_tune_to_i, 0) < average_packets_per_channel:
      sleep_interval_s = 5
    else:
      sleep_interval_s = seconds_between_channel_hop


hop_thread = threading.Thread(target=channel_hop_t, args=())
hop_thread.start()

all_packets = []
per_channel_packet_count_d = {}
physical_info = pyw.phyinfo(interface)

try:
  print(f'Capturing all packets seen by {interface_name}...')
  capture = pyshark.LiveCapture(
    interface=interface_name,
    bpf_filter=bpf_filter,
  )

  while True:
    
    # Metadata
    total_packets = sum([v for k,v in per_channel_packet_count_d.items()])
    average_packets_per_channel = total_packets / max(len(per_channel_packet_count_d), 1)
    print(f'Channel packet count summary ({total_packets:,} total):')
    for k,v in per_channel_packet_count_d.items():
      maybe_star = '*' if k == current_channel else ''
      maybe_inactive = '-' if v < average_packets_per_channel else ''
      print(f'{k}{maybe_star}{maybe_inactive}> {v:,} packets')

    # Sniff; not sure how much packet_count affects input distributions
    for p in capture.sniff_continuously(packet_count=random.choice([1,2,5,10,10,12,12,12,20,20,20])):
      all_packets.append(p)
      per_channel_packet_count_d[current_channel] = per_channel_packet_count_d.get(current_channel, 0) + 1

      #print(f'packet = {p}')
      
      source_ip = maybe(lambda: p.ip.src)
      dest_ip = maybe(lambda: p.eth.dst)
      
      if source_ip is not None and dest_ip is not None:
        # We know we have IP comms, detect type of comms.
        communication_type = 'UNK'
        if hasattr(p, 'udp') and p[p.transport_layer].dstport == '53':
          communication_type = 'DNS'
        elif hasattr(p, 'tcp'):
          if p[p.transport_layer].dstport == '80':
            communication_type = 'Unencrypted HTTP data'

          elif p[p.transport_layer].dstport == '443':
            communication_type = 'Encrypted HTTP data'

          else:
            communication_type = 'Unknown TCP data'

        elif hasattr(p, 'udp'):
          communication_type = 'Unknown UDP data'
        
        print(f'{source_ip} ({enrich_ip_addr(source_ip)}) -> {dest_ip} ({enrich_ip_addr(dest_ip)}): {communication_type}')

except:
  traceback.print_exc()

exit_flag = True

pyw.down(interface)
pyw.modeset(interface, 'managed')
pyw.up(interface)

if len(all_packets) > 0:
  print(f'''

Interact with the variables `capture` and `all_packets` to see what traffic was recorded from {interface_name}!

''')

  variables = locals()
  variables.update(globals())
  code.interact(local=variables)

