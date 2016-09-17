---
title: "WMI: Queries For Incident Response"
tags: [wmi, windows]
date: 2016-04-09T11:30:35-04:00
---
Windows Management Instrumentation, WMI, is a very powerful tool when it comes to doing incident response or general
investigations related to Windows events.

Per [Microsoft](https://msdn.microsoft.com/en-us/library/windows/desktop/aa394582(v=vs.85).aspx)...

>Windows Management Instrumentation (WMI) is the infrastructure for management data and operations on Windows-based operating
systems. You can write WMI scripts or applications to automate administrative tasks on remote computers but WMI also
supplies management data to other parts of the operating system and products, for example System Center Operations
Manager, formerly Microsoft Operations Manager (MOM), or Windows Remote Management (WinRM).


### Setup
---
WMI commands are typically executed from a Windows machine, however there is a WMIC client for linux which works pretty well.
I'm going to make an effort at porting the Windows WMI syntax to the Linux equivalent (and vice versa ) for those that prefer to execute
incident response activities from that type of environment. Please note that there appears to be an issue, possible memory leak,
with the WMIC client for Linux. For example, if you attempt to pull a large amount of data (think of historical event logs),
the Linux WMIC client will crash and only produce partial information. If a large amount of data is being requested,
it's best to use a Windows machine.

Windows:

>WMI should be installed by default on your updated Windows OS.

Linux:

>Review the installation instructions located on [Aldeid.com](https://www.aldeid.com/wiki/Wmic-linux).

Please take into consideration that the credentials used for the following commands will need to have the appropriate
administrative permissions to have successful execution.

### Commands
---
The following commands are to be executed from within a bash shell or windows command prompt. In a following article, we'll
discuss how to create a Python script to automate this process.

For the Windows command, it's assumed the user you are currently logged in as has the appropriate permissions to execute remote WMI commands.

#### Logged On User
**Windows:** ```wmic /node:(computer ip) path Win32_ComputerSystem```

**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "select * from Win32_computersystem"```

#### Check Anti-Virus
**Windows:** ```wmic /node:(computer ip) /namespace:\\root\\SecurityCenter2 path AntiVirusProduct```

**Linux:** ```wmic --namespace=root\\SecurityCenter2 -U (domain)\\(account) //(computer ip) "Select * from AntiVirusProduct"```

#### Check For Running Processes
**Windows:** ```wmic /node:(computer ip) process get | findstr /I (executable name)```

**Linux:** ```wmic --namespace=root\\SecurityCenter2 -U (domain)\\(account) //(computer ip) "Select * from AntiVirusProduct" | grep -i (executable name)```

#### Installed Updates/Hotfixes
**Windows:** ```wmic qfe list full /format:htable > C:\hotfixes.htm```

**Linux:** ```wmic -U (domain)\\(account) //(computer ip) 'Select * from win32_quickfixengineering'```

#### NIC MAC Addresses
**Windows:** ```wmic /node:(computer ip) nic get MACAddress,Description,NetworkAddresses,Manufacturer```

**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "Select * from Win32_NetworkAdapterConfiguration"```

#### MAC Times
**Windows:** ```wmic /node:(computer ip) path cim_datafile where "Drive='C'"```

**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "Select LastModified, LastAccessed, CreationDate, InstallDate, FileSize, FileType, Name from cim_datafile where Drive = 'C:'"```


#### PC Restart Event Logs
**Linux:** ```wmic -U (domain)\\(account) //(computer_ip) "Select * from Win32_NTLogEvent where (EventCode='1074' or EventCode='6013') and TimeGenerated >='20150101000000.000000-000' and TimeGenerated <= '20150106000000.000000-000'"```

#### Successful Login Event Logs
**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "Select InsertionStrings from Win32_NTLogEvent where (EventCode='4624') and TimeGenerated >='20150101000000.000000-000' and TimeGenerated <= '20150106000000.000000-000'"```


#### Remote PC Time
**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "Select hour,minute,second from win32_localtime"```

#### List Local Accounts
**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "select * from Win32_UserAccount Where LocalAccount=True"```

#### List Local Groups/Users
**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "select * from Win32_GroupUser"```

#### Operating System Details including Hostname
**Linux:** ```wmic -U (domain)\\(account) //(computer ip) "Select * from Win32_OperatingSystem"```

#### View Installed Programs
**Windows:** ```wmic /node:(computer ip) product get /format:csv > C:\output.csv```

#### Execute Remote Commands
**Windows:** ```wmic /node:(computer ip) process call create "netstat.exe -ano > C:\output.txt"```

