---
title: "Python: Wireless Sniffing With Scapy"
categories: blog
tags: [python, scapy]
date: 2015-04-21T10:39:55-04:00
---

Before we dive into it, I'd first like to take a momemnt to make sure whomever follows this tutorial has the correct components installed. I will be performing this on an Ubuntu system, but really, any platform should be able to be used, you'll just have to follow the recommended intallation steps for your operating system.

### Setup
------
1. We'll be using Python 2.7.
  * ```
  python -V #for your version
  ```
2. Scapy will be the main module used.
  * Download [Scapy](https://bitbucket.org/secdev/scapy/downloads/scapy-2.3.1.zip)
  * Extract archive and cd into the folder
  * ```
  sudo python setup.py install
  ```
3. Termcolor will colorize our output.
  * ```
  sudo pip install termcolor
  ```
4. We'll be using airmon-ng to setup our wireless card.
  * ```
  sudo apt-get install aircrack-ng
  ```

### The Code
------

Now that we've installed everything we need, lets start stepping through the code!

We'll begin by first specifying our interpreter, followed by importing the modules we'll use. You'll probably notice the 3rd line for logging and think "What the heck is that for?" Without this line, whenever the script is ran, an annoying message will pop up regarding Scapy IPv6 routes. The logging line will quite that, while still alerting to any serious errors that may occur.

```python
#!/usr/bin/env python
import logging
# Silence Scapy IPv6 message at runtime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from termcolor import colored, cprint
import argparse
import datetime
import sys
```

We'll then move on to setting up some of the configuration with variables we'll use later on.

In order to gather more information and profile wireless connections, we'll parse a file that correlates MAC addresses to vendors based on what we sniff. These combinations will be stored into a dictionay as a key/value pair for searching later.

```python
# Keep track of unique mac addresses
mac_list = []

# Vendors
ven_dic = {}

# Interface to monitor. Once you have your wireless
# nic listening, make sure to replace the variable string
# with your listening wireless nic.
# EX: iwconfig #to find your wireless nic (eg: wlan1)
# EX: sudo airmon-ng start wlan1 (Or the wireless nic you saw in previous step)
# EX: iwconfig #to find out the name of the nic airmon created
interface = "mon0"

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-V", "--verbose", help="different formatting and detailed output", action="store_true")
args = parser.parse_args()
```

Now lets get a for loop going to read through our vendors.txt file so we can parse the input and assign it to the ven_dic dictionary we created earlier.

Please make sure the vendors.txt file is located in the same directory as the python script so that it may access it properly using the default setup.

Download: [vendors.txt]({{ site.baseurl }}/files/vendors.txt)

```python
# Read in vendors and add to ven_dic
with open("vendors.txt") as vendors:
    for line in vendors:
        join_line = " ".join(line.split())
        ven_mac = join_line.split(" ")[0]
        ven_name = join_line.split(" ")[1]
        ven_dic[ven_mac] = ven_name
```

We'll now start getting into defining our functions. If you are  unfamiliar with functions, think of them as basically routines. They can be called upon to perform actions that are repetative. They can also accept arguments or paramaters. For instance, these functions have two arguments, mac and ssid. We'll pass in these items and the function will return information based on what we feed into it.

If this doesn't make sense, don't worry. It should be cleared up pretty shortly.

```python
# Function to print if access point is detected
def AccessPointPrint(mac, ssid):
    # Check to see if we know the vendor
    if mac[0:8].upper() in ven_dic.keys():
        vendor = ven_dic[mac[0:8].upper()]
    else:
        vendor = "unknown"
        
    # If verbose was used, print out the format below
    if args.verbose:
        print "-" * 146 + "\n"
        print colored("* I SEE YOU! *\n", "red", attrs=["bold"])
        print "TIME    :", datetime.datetime.now()
        print "MAC     :", mac
        print "TYPE    :", colored("ACCESS POINT", "yellow", attrs=["bold"])
        print "SSID    :", colored(ssid, "green", attrs=["bold"])
        print "CHIPSET :", vendor
        # I recommend customizing the note below to your liking.
        print "NOTE    : This is an access point that is broadcasting its wireless SSID for client connection. "
        
    # Else print the default format
    else:
        print colored("* I SEE YOU! * ", "red", attrs=["bold"]) + "%s (%s)" % (mac, vendor), "as an", \
            colored("ACCESS POINT", "yellow", attrs=["bold"]), "for SSID:", colored(ssid, "green", attrs=["bold"])

# Function to print if client probe is detected
def ProbePrint(mac, ssid):
    # Check to see if we know the vendor
    if mac[0:8].upper() in ven_dic.keys():
        vendor = ven_dic[mac[0:8].upper()]
    else:
        vendor = "unknown"
        
    # If verbose was used, print out the format below
    if args.verbose:
        print "-" * 146 + "\n"
        print colored("* I SEE YOU! *\n", "red", attrs=["bold"])
        print "TIME    :", datetime.datetime.now()
        print "MAC     :", mac
        print "TYPE    :", colored("PROBING", "yellow", attrs=["bold"])
        print "SSID    :", colored(ssid, "green", attrs=["bold"])
        print "CHIPSET :", vendor
        # I recommend customizing the note below to your liking.
        print 'NOTE    : '  '''This traffic is from an asset attempting to connect to a wireless network it has seen before.
          The wireless packets are able to be intercepted and parsed to reveal a network the device trusts. An "Evil-Twin"
          attack can occur where a malicious actor creates an access point with the same SSID name to intercept credentials.'''
          
    # Else print the default format
    else:
        print colored("* I SEE YOU! * ", "red", attrs=["bold"]) + "%s (%s)" % (mac, vendor), \
            colored("PROBING", "yellow", attrs=["bold"]), "for SSID:", colored(ssid, "green", attrs=["bold"])
```

Awesome. Now that we have our functions that will print our output depending on what wireless traffic is captured, we need to define one more function that will really be doing all of the work.

```python
def PacketAnalyzer(pkt):

    # Check to make sure we got an 802.11 packet
    if pkt.haslayer(Dot11):

        # Check to see if it's an access point beacon
        if pkt.type == 0 and pkt.subtype == 8:
            # Check to see if we have seen the MAC address before, if not, continue with printing
            if pkt.addr2 not in mac_list:
                mac_list.append(pkt.addr2)
                AccessPointPrint(pkt.addr2, pkt.info)

        # Check to see if it's a device probing for networks
        if pkt.haslayer(Dot11ProbeReq):
            # Check to see if we have seen the MAC address before, if not, continue with printing
            if pkt.addr2 not in mac_list:
                mac_list.append(pkt.addr2)
                # Make sure SSID is not blank
                if pkt.info != "":
                    ProbePrint(pkt.addr2, pkt.info)
```

We're almost done now! Just one more line to add. This line uses Scapy's sniff function which takes in the interface to listen on (the variable we set at the beginning of the script), our PacketAnalyzer function (prn tells Scapy to send the packet to our function), and a store value of 0 which insures the packets aren't stored in memory so as to not hog resources.

Using this, once the script is executed, it will run continuosly, sniff wireless packets, and add the MAC address to the list so as to not repeatedly print the same device.

```python
sniff(iface=interface, prn=PacketAnalyzer, store=0)
```

### Running
------

You're done! Now it's time to see your creation.

There are two options to running this script, with or without the -V or --verbose option. But first, we have to get the wireless nic into a "listening" state to intercept packets and also edit the interface variable if your listening nic is different then what we added by default.

1. Find your wireless nic with.
  * ```iwconfig #eg: wlan1```
2. Use airmon to set your wireless nic to listen
  * ```sudo airmon-ng start wlan1 #or w/e wireless nic you saw in step 1```
3. Use iwconfig again to see what nic airmon created for you.
  * ```iwconfig #eg: mon1```
4. If different then what's in the "interface" variable,
change the string to your interface.

Now run your script and see the results!

### What now?
------

It's up to you! Here are some challenges if you are up for it.

1. Try condensing the functions to 1 or 2 and use "if" statements inside of them to determine what to do.

2. Instead of having to manually edit the script with your listening wireless nic, try to add another script argument (maybe -i, --interface) that is given a value at runtime. This will allow you to specify an interface as a script argument, like --verbose.

3. I don't believe Scapy channel hopes, so try creating an alternate script to rotate through wireles channels. Maybe a cron job?

4. Maybe you only want to store the MAC addresses of the access points and want to print all other traffic, even if it's potentially duplicates. You can make it happen!