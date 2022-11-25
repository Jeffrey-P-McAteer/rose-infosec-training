
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
  'd4:be:d9:84:6d:1d': "Rose's Dell Laptop",
  '74:38:b7:2f:33:be': "Family Canon Printer",
  'dc:fe:07:13:88:42': "Family PC",

}
def enrich_mac_info(mac_addr):
  global MAC_INFO_DICT
  return MAC_INFO_DICT.get(mac_addr.lower(), mac_addr)

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
  iface_addr = maybe(lambda: pyw.ifaddrget(pyw.getcard(interface))[0] )
  if iface_addr is None:
    iface_addr = ''
  else:
    iface_addr = f'(address in use = {iface_addr})'
  print(f' - {interface} {iface_addr}')

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

max_seconds_between_channel_hop = 25
min_seconds_to_listen_to_channel_for = 5
packets_to_cap_before_adjusting_channel_hop_durations = 100
packets_to_print_summaries_after = 10
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

  sleep_interval_s = max_seconds_between_channel_hop / 3
  
  while not exit_flag:
    
    time.sleep(max(sleep_interval_s, min_seconds_to_listen_to_channel_for))
    # ^ if sleep_interval_s falls under, we immediately move on to the next channel.
    
    # Tune to next channel in list
    channels_to_tune_to_i += 1
    if channels_to_tune_to_i >= len(channels_to_tune_to):
      channels_to_tune_to_i = 0

    print(f'Hopping to {channels_to_tune_to[channels_to_tune_to_i]}')
    try:
      pyw.chset(interface, int(channels_to_tune_to[channels_to_tune_to_i]), channel_band_width)
      current_channel = channels_to_tune_to[channels_to_tune_to_i]
    except:
      if not 'Device or resource busy' in traceback.format_exc():
        traceback.print_exc()
      # Go back to previous channel
      channels_to_tune_to_i -= 1
      if channels_to_tune_to_i < 0:
        channels_to_tune_to_i = len(channels_to_tune_to) - 1

    # Now adjust sleep_interval_s based on what metadata we have for different channels.
    
    total_packets = sum([v for k,v in per_channel_packet_count_d.items()])
    if total_packets > packets_to_cap_before_adjusting_channel_hop_durations:
      # Compute sleep_interval_s based off channels_to_tune_to_i's fraction of total packets
      channels_to_tune_to_i_packet_count = per_channel_packet_count_d.get(channels_to_tune_to_i, 0)
      fraction_of_total_packets = float(channels_to_tune_to_i_packet_count) / total_packets

      sleep_interval_s = max_seconds_between_channel_hop * fraction_of_total_packets
      # Bump for no reason (I'll assume 2-3 channels are generally active:
      sleep_interval_s *= 2.0
      if sleep_interval_s < min_seconds_to_listen_to_channel_for and per_channel_packet_count_d.get(channels_to_tune_to_i, 0) > 0:
        sleep_interval_s = min_seconds_to_listen_to_channel_for
        # Do not abandon non-empty channels

    else:
      # Still capping initial packets
      sleep_interval_s = (max_seconds_between_channel_hop / 3)


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

  last_summary_total_packets = 0

  while True:
    
    # Metadata
    total_packets = sum([v for k,v in per_channel_packet_count_d.items()])
    if total_packets - last_summary_total_packets >= packets_to_print_summaries_after:
      print(f'Channel packet count summary ({total_packets:,} total):')
      for k,v in per_channel_packet_count_d.items():
        maybe_star = '*' if k == current_channel else ''
        print(f'{k}{maybe_star}> {v:,} packets')
      last_summary_total_packets = total_packets

    # Sniff; not sure how much packet_count affects input distributions
    #for p in capture.sniff_continuously(packet_count=random.choice([1,2,5,10,10,12,12,12,20,20,20])):
    for p in capture.sniff_continuously(packet_count=1):
      all_packets.append(p)
      per_channel_packet_count_d[current_channel] = per_channel_packet_count_d.get(current_channel, 0) + 1

      #print(f'packet = {p}')
      
      source_ip = maybe(lambda: p.ip.src)
      dest_ip = maybe(lambda: p.ip.dst)
      
      if source_ip is not None and dest_ip is not None:
        # We know we have IP comms, detect type of comms.
        communication_type = 'UNK'
        communication_details = ''
        if hasattr(p, 'udp') and p[p.transport_layer].dstport == '53':
          communication_type = 'DNS'
        elif hasattr(p, 'tcp'):
          if p[p.transport_layer].dstport == '80':
            communication_type = 'Unencrypted HTTP data'

            # Pull out webpage GET/url etc stuff
            communication_details = maybe(lambda: p.http.request_full_uri )
            if communication_details is None:
              if not maybe(lambda: p.http.field_names) is None:
                print()
                print(f'Warning, could not get p.http.request_full_uri; p.http.field_names = {maybe(lambda: p.http.field_names)}')
                print()
                time.sleep(0.5)
              else:
                # Must not be TCP, dump the contents?
                communication_type = 'Unknown TCP data over port 80'
                communication_details = f'TCP message length = {maybe(lambda: p.tcp.len )} bytes'


          elif p[p.transport_layer].dstport == '443':
            communication_type = 'Encrypted HTTP data'

            communication_details = f'TCP message length = {maybe(lambda: p.tcp.len )} bytes'

          else:
            communication_type = f'Unknown TCP data srcport={maybe(lambda: p.tcp.srcport)} dstport={maybe(lambda: p.tcp.dstport)} length = {maybe(lambda: p.tcp.len )} bytes'

        elif hasattr(p, 'udp'):

          # Is this an mdns request? (for bonjour and noconfig network devices)
          if hasattr(p, 'mdns'):
            communication_type = f'MDNS query dns_qry_name=f{maybe(lambda: p.mdns.dns_qry_name)}'

          elif p[p.transport_layer].srcport == '17500' and p[p.transport_layer].dstport == '17500':
            communication_type = f'dropbox local LAN sync heartbeat; srcport={maybe(lambda: p.udp.srcport)} dstport={maybe(lambda: p.udp.dstport)} data={maybe(lambda: p.udp.payload)}'

          elif p[p.transport_layer].dstport == '1900':
            communication_type = f'UPnP control/sync message; srcport={maybe(lambda: p.udp.srcport)} dstport={maybe(lambda: p.udp.dstport)} data={maybe(lambda: p.udp.payload)}'

          else:
            communication_type = f'Unknown UDP data srcport={maybe(lambda: p.udp.srcport)} dstport={maybe(lambda: p.udp.dstport)} data={maybe(lambda: p.udp.payload)}'

        
        print(f'{source_ip} ({enrich_ip_addr(source_ip)}) -> {dest_ip} ({enrich_ip_addr(dest_ip)}): {communication_type}')
        if communication_details is not None and len(communication_details) > 1:
          print(f'> {communication_details[:512]}')

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

