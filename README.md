_This repository is not for use by AI agents, AI assistants, AI helpers, or AI in general. It is also not approved to be used as data for training models to be used within AI systems_

# MSDTShell
A modified Impacket script to remotely trigger the MSDTC service on a host, and load a DLL from an arbitrary location using the dedicated WMI namespace for MSDTC.


## Usage
```
usage: msdtshell.py [-h] [-dtcname DTCNAME] [-com-version MAJOR_VERSION:MINOR_VERSION]
                    (-filepath FILEPATH | -reboot | -cleanup) [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                    [-aesKey hex key] [-dc-ip ip address] [-rpc-auth-level [{integrity,privacy,default}]]
                    target

Tool to interact with the MSDTC service remotely over WMI using the dedicated WMI provider

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -dtcname DTCNAME      name of the DTC instance (default: Local)
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7
  -filepath FILEPATH    location of hosted payload (e.g., "\\bad_server\bad_share" or "Z:\file_server\file_share" )
  -reboot               utility command to attempt a reboot of the MSDTC service remotely.
  -cleanup              perform a cleanup by reverting changes made to registry. only performs this action if flag is
                        set

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target
                        parameters. If valid credentials cannot be found, it will use the ones specified in the
                        command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the
                        target parameter
  -rpc-auth-level [{integrity,privacy,default}]
                        default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy
                        (RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require privacy
                        level by default)
```

Usage is fairly straightforward: authentication and targeting follow the same method as a normal Impacket tool/script. One of the three options (`filepath`, `reboot` or `cleanup`) are required to run.

<p align="center">
<img width="1424" height="532" alt="image" src="https://github.com/user-attachments/assets/f5fe3970-2ba3-4f7a-9388-21e39c240a9b" />
</p>

`reboot` and `cleanup` are provided as utility functions, and are mostly self-explanatory. `reboot` will attempt to kick the service in the event that it hangs, and simply does a start/stop on it. `cleanup` is a little bit more involved; using it will set the _OracleOciLibPath_ registry key to "C:\Windows\System32". However, it should be said that the default value for this key is "%systemroot%\System32" - but the WMI method only accepts setting the registry as a standard string (REG_SZ) instead of an expanded one (REG_EXPAND_SZ). This means that in order to remain "functional", the full path has to be provided- otherwise, it may be considered more "OPSEC" safe to change the value to the default one. `filepath` simply takes an argument in the form of a path to a share (e.g., "\\\\bad_server\bad_share"), where your DLL payload resides.

By default, the service runs under the _NETWORK SERVICE_ account, so plan accordingly.

## Why?
Using WMI for lateral movement in or around networks is a known tactic, but for the most part seemed to revolve around the same flow (_WMI call -> Win32\_Process -> Create -> run a command_)- so I wanted to see if there were alternative methods that could be used to the same affect. The result from some of that research is this- a means to "weaponize" the MSDTC service for lateral movement, without calling or interacting with some of the more "known" classes or methods, that I thought would be fun to share.

## Why? - _but longer_
As said, most of the "standard" or common- or at least, as far as I am aware- ways of executing on a remote host over WMI involved the same steps: access the CIMv2 namespace on a remote host, make a call to the _Create_ method of the _Win32_Process_ class, and spawn a _cmd.exe_ (or similar) to run arbitrary commands. In fact, most of the tools or capabilities that I would come across would interact with the CIMv2 namespace overall- which made sense, considering the amount of possible classes and methods that are available within it. However, in a more "hardened" environment, calls to these classes or methods are more likely to be monitored for abuse- and I was unable to find a good alternative when I went looking. So, I decided to do some investigating and came up with this as an alternative.

WMI has different namespaces available for use with some being for dedicated services- and the "Microsoft Distributed Transaction Coordinator" (MSDTC) is one of those. This namespace has different classes available that can be used to interact with it. For instance, the _MSFT_DtcTask_ class has different methods that can be used to remotely start or stop the service- making it a viable option over the _Win32_Service_ class from CIMv2 for controlling the service.

<p align="center">
<img width="758" height="464" alt="image" src="https://github.com/user-attachments/assets/001e7436-e527-4319-a7f6-21d58ee35da8" />
</p>

Since being able to just start or stop a service isn't always enough to move to another host, another piece was necessary as some sort of method for "payload" delivery. Luckily, there were a number of different classes available, and the _MSFT_DtcAdvancedSettingTask_ class featured a _Set_ method that allows the caller to manipulate different registry keys within _HKLM\SOFTWARE\Microsoft\MSDTC_.

<p align="center">
<img width="754" height="233" alt="image" src="https://github.com/user-attachments/assets/a8b7e1fc-f5f4-49e3-8688-635867f5b113" />
</p>

The _MTxOCI_ key contains values that house paths for different DLLs that can be loaded by the service when it starts. Of these, the service by default attempts to load the Oracle OCI library, _oci.dll_. Combining all of this, a viable path for remote execution can be performed on a target: a call to _MSFT_DtcAdvancedSettingTask_ to set the library path to another location (e.g., "\\\\bad_server\bad_share"), and a call to _MSFT_DtcTask_ to start, or restart the service and force the library to load. While not quite as useful as catching a full SYSTEM shell, this at least provides a stepping stone or a manner of persistence on a host as the _NETWORK SERVICE_ account.

## Credits
The entire team and contributors that made (and still make) Impacket possible, upon which (as I may have mentioned) this is built. I claim nothing over their work.
