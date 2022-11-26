
#
# This script hops radio channels to enumerate all MAC/IP pairs
# and record them plus a friendly name (see )
#

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
import os

# Our helper
from libhelper import importinate, input_with_prefill, maybe, with_memory
from enrich import enrich_mac, enrich_any

# 3rdparty code
pyshark = importinate('pyshark')
pyric = importinate('pyric', 'PyRIC') # TODO investigate https://github.com/wifiphisher/wifiphisher ?
import pyric.pyw as pyw


wireless_ifaces = pyw.winterfaces()
print(f'Detected {len(wireless_ifaces)} interfaces:')

for i, interface in enumerate(wireless_ifaces):

  iface_ssid = maybe(lambda: pyw.link(pyw.getcard(interface))['ssid'] )
  iface_addr = maybe(lambda: pyw.ifaddrget(pyw.getcard(interface))[0] )
  iface_bandwidth = maybe(lambda: pyw.devinfo(pyw.getcard(interface))['CHW'] )

  if iface_ssid is None:
    iface_ssid = ''
  else:
    iface_ssid = f'(Connected SSID = {iface_ssid})'
  
  if iface_addr is None:
    iface_addr = ''
  else:
    iface_addr = f'(address in use = {iface_addr})'
  
  if iface_bandwidth is None:
    iface_bandwidth = ''
  else:
    iface_bandwidth = f'(current bandwidth = {iface_bandwidth})'
  
  print(f' - {interface} {iface_ssid} {iface_addr} {iface_bandwidth}')


interface_name = wireless_ifaces[len(wireless_ifaces)-1] if len(wireless_ifaces) > 0 else 'Error: no interfaces!' # str(input('Which interface would you like to capture? '))
history_interface_name = with_memory(lambda m: m.get('interface_name', None))
if history_interface_name is not None:
  interface_name = history_interface_name

print(f'Enter an interface name to capture with:')
interface_name = input_with_prefill('> ', interface_name).strip()
interface = pyw.getcard(interface_name)
if not 'monitor' in pyw.devmodes(interface):
  print(f'Error, {interface_name} does not have monitor mode available! Modes: {pyw.devmodes(interface)}')
  sys.exit(1)

# Save interface
with_memory(lambda m: m.update({'interface_name': interface_name}) )

interface_channels = [x for x in pyw.devchs(interface) if not x is None]
print(f'interface_channels = {interface_channels}')

channel_band_width = '20'
print(f'Enter the bandwidth (One of 20,40,40+); for each channel this defines how much interference is accepted from neighboring channels, the higher the width the more neighbor channels will be captured at once.')
channel_band_width = input_with_prefill('> ', channel_band_width).strip()

if '20' in channel_band_width:
  channel_band_width = 'HT20'
elif '40' in channel_band_width and not '+' in channel_band_width:
  channel_band_width = 'HT40-'
else:
  channel_band_width = 'HT40+'
print(f'channel_band_width = {channel_band_width}')


print('Enabling monitor mode...')
pyw.down(interface)
pyw.modeset(interface, 'monitor')
pyw.up(interface)

capture = pyshark.LiveCapture(
  interface=interface_name, bpf_filter='',
)

channel_packets_d = {}
for channel in interface_channels:
  channel_packets_d[channel] = []

active_channel = interface_channels[0]

last_wlan_src_addr = ''

# used in capture.apply_on_packets
def with_packet(pkt):
  global active_channel
  global last_wlan_src_addr
  #print(f'Channel {active_channel} packet = {}')
  wlan_src_addr = maybe(lambda: pkt.wlan.addr )
  try:
    protocol =  pkt.transport_layer
    src_addr = pkt.ip.src
    src_port = pkt[pkt.transport_layer].srcport
    dst_addr = pkt.ip.dst
    dst_port = pkt[pkt.transport_layer].dstport
    print(f'Channel {active_channel}: {protocol} wlan.addr={wlan_src_addr} {src_addr}:{src_port} --> {dst_addr}:{dst_port}')
  except AttributeError as e:
    #print(f'Channel {active_channel}: non-tcp/ip packet: {dir(pkt)}')
    #print(f'Channel {active_channel}: non-tcp/ip packet: transport_layer={maybe(lambda: pkt.transport_layer)} wlan={maybe(lambda: pkt.wlan)} wlan={maybe(lambda: [k+":"+str(maybe(lambda: f"pkt.wlan.{k} = {getattr(pkt.wlan, k)}")) for k in dir(pkt.wlan)] )}')
    pkt_contents = str(pkt)
    if 'RADIOTAP' in pkt_contents:
      pkt_contents = 'RADIOTAP'
    else:
      pkt_contents = pkt_contents[:64]
    if last_wlan_src_addr != wlan_src_addr:
      print(f'Channel {active_channel}: non-ip packet from {wlan_src_addr} ({enrich_mac(wlan_src_addr)}): {pkt_contents}')
      last_wlan_src_addr = wlan_src_addr


# Assign callback
def apply_thread():
  global capture
  capture.apply_on_packets(with_packet)

apply_t = threading.Thread(target=apply_thread)
apply_t.start()

exit_flag = False
while len(interface_channels) > 0 and not exit_flag:
  try:
    channels_to_remove = []
    for channel in interface_channels:
      print(f'Scanning channel {channel}')

      max_tune_retries = 6
      while max_tune_retries > 0:
        max_tune_retries -= 1
        try:
          #pyw.chset(interface, int(channel), channel_band_width)
          pyw.chset(interface, int(channel))
          active_channel = channel
          break
        except:
          traceback.print_exc()
          time.sleep(1.5)

      if max_tune_retries < 1:
        print(f'Removing channel {channel} that this card has significant difficulty with...')
        channels_to_remove.append(channel)
        continue

      # Capture 10 seconds worth of packets
      time.sleep(10)

    for bad_channel in channels_to_remove:
      interface_channels.remove(bad_channel)

  except:
    traceback.print_exc()
    if 'Keyboard' in traceback.format_exc():
      exit_flag = True

  time.sleep(0.1)

print('Disabling monitor mode...')
pyw.down(interface)
pyw.modeset(interface, 'managed')
pyw.up(interface)

print('Done!')

