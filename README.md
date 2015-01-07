# Windows Firewall Hook Driver Enumeration
Tools to enumerate Windows Firewall Hook Drivers on Windows 2000, XP and 2003.

We've seen a malicious code sample which uses this technique.

## The Hooking Technique

The Windows Firewall Hook functionality in XP/2003 technique [1][2][3][4][5] uses an IOCTL of IOCTL_IP_SET_FIREWALL_HOOK sent to \Device\Ip

```
#define FSCTL_IP_BASE     FILE_DEVICE_NETWORK

#define _IP_CTL_CODE(function, method, access) 
            CTL_CODE(FSCTL_IP_BASE, function, method, access)

#define IOCTL_IP_SET_FIREWALL_HOOK  
            _IP_CTL_CODE(12, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

[1] https://briolidz.wordpress.com/2011/12/20/network-traffic-filtering-technologies-for-windows/
[2] http://kosh.la/?p=28
[3] http://www.codeproject.com/Articles/8675/An-Adventure-How-to-implement-a-Firewall-Hook-Driv
[4] http://www.openrce.org/blog/view/453/function.session-start
[5] http://msdn.microsoft.com/en-us/library/windows/hardware/ff546499%28v=vs.85%29.aspx


## Volatility Plugin
We produced a Volatility Plugin to enumerate

```
[FWHook] Found tcpip.sys at offset 0x17b7098 with DllBase 0xf117d000
[FWHook] PE Header Offset: 0x0000d8
[FWHook] Image Base Address: 0x010000
[FWHook] FQ Block Address: 0xf11be860
[FWHook] FQ Counter Address: 0xf11be880
[FWHook] FQ Counter Value: 16 0x000010
[FWHook] Final FQ Block Address: 0xf11be870
[FWHook] Total hooks registered 3
[FWHook] -----------------------------------------------------------------------------------
[FWHook] Call Out Address: 0xf0582246
[FWHook] Module Base Address: 0xf0580000
[FWHook] Module DLL Name dump_dumpfve.sys
[FWHook] Module Binary Path \??\C:\WINDOWS\system32\drivers\dump_dumpfve.sys
[FWHook] -----------------------------------------------------------------------------------
[FWHook] Call Out Address: 0xf103c6dc
[FWHook] Module Base Address: 0xf1027000
[FWHook] Module DLL Name ipnat.sys
[FWHook] Module Binary Path \SystemRoot\system32\DRIVERS\ipnat.sys
[FWHook] -----------------------------------------------------------------------------------
[FWHook] Call Out Address: 0xf0582270
[FWHook] Module Base Address: 0xf0580000
[FWHook] Module DLL Name dump_dumpfve.sys
[FWHook] Module Binary Path \??\C:\WINDOWS\system32\drivers\dump_dumpfve.sys
```

## Windows Native Tool
We've producted a Windows native driver and commmand line utility that will be release shortley