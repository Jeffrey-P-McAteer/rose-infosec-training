
import traceback

# Responsible for taking partial target info and looking up / remembering the 
# previously known information
from libhelper import importinate

# used to identify unknown device manufacturers
mac_vendor_lookup = importinate('mac_vendor_lookup', 'mac-vendor-lookup')
from mac_vendor_lookup import MacLookup

getmac = importinate('getmac', 'get-mac')


MAC_INFO_DICT = {
  '60:f2:62:e5:ee:94': "Jeffrey's thinkpad wlan1",
  '3c:33:00:20:48:02': "Jeffrey's thinkpad wlan1 (removable 2.4ghz card)",
  'c8:c7:50:ec:4e:11': "Primary Gateway wlan0 (serves 5ghz and 2.4ghz spectrums)", # Saw c8:c7:50:ec:4e:11 using 2.4ghz network
  'd4:be:d9:84:6d:1d': "Rose's Dell Laptop",
  '74:38:b7:2f:33:be': "Family Canon Printer",
  'dc:fe:07:13:88:42': "Family PC",

}
MAC_m = MacLookup()

def enrich_mac(mac_addr):
  global MAC_INFO_DICT
  mac_addr = mac_addr.lower()
  if mac_addr in MAC_INFO_DICT:
    return MAC_INFO_DICT[mac_addr]
  else:
    try:
      return MAC_m.lookup(mac_addr)
    except:
      if not 'This event loop is already running' in traceback.format_exc():
        traceback.print_exc()
  return mac_addr

def enrich_ip(ip_addr):
  mac_addr = ip_addr
  if ':' in ip_addr:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip6=ip_addr))
  else:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip=ip_addr))
  if mac_addr is None:
    mac_addr = ip_addr
  return enrich_mac_info(mac_addr)


def enrich_any(identifier): # TODO
  mac_addr = identifier
  if ':' in identifier:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip6=identifier))
  else:
    mac_addr = maybe(lambda: getmac.get_mac_address(ip=identifier))
  if mac_addr is None:
    mac_addr = identifier
  return enrich_mac_info(mac_addr)

