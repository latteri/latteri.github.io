---
title: "Netsh: Native Windows Packet Capture"
categories: blog
tags: [netsh, windows]
date: 2016-02-26T14:12:02-04:00
---
At some point, you may find yourself in the same shoes I was in and think to yourself "Is it possible to acquire a packet capture on a Windows machine using native tools?".  It's not very common that the average end-user is going to have items like Tshark or Tcpdump installed on their box to work with from the command line. So, if you aren't collecting the neccessary packets through a centralized aggregater and would like to have minimal disturbence on the target machine, what can you do?

Netsh to the rescue!

The following is what I went through recently and Rob VandenBrink's artcile over at the InfoSec Handlers Diary Blog was a fantastic resource.

### What's Netsh?
---
Aren't familiar with Netsh? Let's see what Microsoft has to say about it...

"Netsh is a command-line scripting utility that allows you to, either locally or remotely, display or modify the network configuration of a computer that is currently running. Netsh also provides a scripting feature that allows you to run a group of commands in batch mode against a specified computer. Netsh can also save a configuration script in a text file for archival purposes or to help you configure other servers."

Hmmm, I don't see anything specifying that it has the ability to create packet captures. Lets take a look at the help options


```C:\Users\user>netsh /?```

```batch
Usage: netsh [-a AliasFile] [-c Context] [-r RemoteMachine] [-u [DomainName\]Use
rName] [-p Password | *] [Command | -f ScriptFile]
```

The following commands are available:

```batch
Commands in this context:
?              - Displays a list of commands.
add            - Adds a configuration entry to a list of entries.
advfirewall    - Changes to the netsh advfirewall context.
branchcache    - Changes to the netsh branchcache context.
bridge         - Changes to the netsh bridge context.
delete         - Deletes a configuration entry from a list of entries.
dhcpclient     - Changes to the `netsh dhcpclient' context.
dnsclient      - Changes to the netsh dnsclient context.
dump           - Displays a configuration script.
exec           - Runs a script file.
firewall       - Changes to the netsh firewall context.
help           - Displays a list of commands.
http           - Changes to the netsh http context.
interface      - Changes to the netsh interface context.
ipsec          - Changes to the netsh ipsec context.
lan            - Changes to the netsh lan context.
mbn            - Changes to the netsh mbn context.
namespace      - Changes to the netsh namespace context.
nap            - Changes to the netsh nap context.
netio          - Changes to the netsh netio context.
p2p            - Changes to the netsh p2p context.
ras            - Changes to the netsh ras context.
rpc            - Changes to the netsh rpc context.
set            - Updates configuration settings.
show           - Displays information.
trace          - Changes to the netsh trace context.
wcn            - Changes to the netsh wcn context.
wfp            - Changes to the netsh wfp context.
winhttp        - Changes to the netsh winhttp context.
winsock        - Changes to the netsh winsock context.
wlan           - Changes to the netsh wlan context.
```

Nothing to obvious, but lets look into the trace option help


```C:\Users\user>netsh trace /?```

The following commands are available:

```batch
Commands in this context:
?              - Displays a list of commands.
convert        - Converts a trace file to an HTML report.
correlate      - Normalizes or filters a trace file to a new output file.
diagnose       - Start a diagnose session.
dump           - Displays a configuration script.
help           - Displays a list of commands.
show           - List interfaces, providers and tracing state.
start          - Starts tracing.
stop           - Stops tracing.
```

Perhaps we're onto something here. What does microsoft have to say about the trace option for netsh?

[Microsoft Netsh Trace](https://msdn.microsoft.com/en-us/library/windows/desktop/dd569142(v=vs.85).aspx)

With the trace option, we're able to specify what type of trace we want, along with additional filters down to what IP addresses are of interest for the capture.

A full list of capture filters can be obtained with the following. 

```netsh trace show capturefilterhelp```

### Getting It To Run
---
Awesome. Now we need to get it to run on the machine...
The way I went about it was through the use of PsExec, a great remote admin tool apart of the PsTools suite by Mark Russinovich. I should also note that admin priveledges will be needed to accomplish this.

```psexec.exe -accepteula \\\\remoteip\c$ cmd.exe```

Now that we're on the machine, lets get a trace going

```netsh trace start capture=yes Ethernet.Type=IPv4  IPv4.Address=X.X.X.X```

Once we think we got what we need, lets stop the trace.

```netsh trace stop```
	
### Viewing What You Capture
---
The output will be in an .ETL format. In order to view it, you must utilize Microsoft's Message Nalayzer application. As Rob mentions within his post, you can then leverage the export feature to get a PCAP version for Wireshark or TCPDUMP usage.