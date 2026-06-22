---
layout: post
title:  "Proxmox and Adversaries | Part 1"
date:   2026-06-13 12:26:20 +0100
categories: proxmox
---
### Starting..

This post is joined with an overview kept here: [Adversaries in proxmox](https://www.goblinloot.net/2026/06/adversaries-in-proxmox-goblin-diary-3.html)

🌟 Testing your own detections or want to practice hunting? Upload the full log to your SIEM:
[sim_proxmox_full_log.json]({{ site.url }}\assets\proxmox_death\sim_proxmox_full_log.json)

Proxmox does not afford its users native controls for monitoring process executions nor file writes unlike VMWare ESXI and as such auditd or other similar technologies must be deployed. Using auditd we can easily capture adversary behaviour and develop a series of detection ideas that compliment each other.

I have utilised a parser to better prepare the logs for validation and in this parser ‘PROCTILE’ events are decode from hexadecimal to full strings. You must also do this using your own tools if you wish to process the events in the same capacity as I have in this blog.

## **Initial Access and Local System Discovery**

Proxmox appliances can utilise the same user management provider for both terminal access and the virtual environment graphical interface. In this example the adversary has gained access to a Proxmox appliance through a remote SSH session but has chosen to pivot to the graphical interface with the knowledge that interactions are harder to trace and therefore less likely to be logged.

To maximise our coverage of this horizontal movement we can utilise the pveproxy and journald. These logs store API requests the daemon processes and executes.


### GUI Authentication Logs:

In our example the adversary has attempted to brute force valid accounts across a number of domains. This is easily discoverable through the journald logs for ‘pvedaemon.service’. Aggregating on the key fields creates a simple view:

{% highlight js %}
regex(field=@rawstring, regex="rhost=(?:::ffff:)?(?<ip>.*?)\s+user=(?<user>[^@\s]+)(?:@(?<domain>[a-zA-Z0-9.\-]+))?")
// no realm means local host auth was tried
| case{
  domain != *
  | domain := "pam"; *
  
}
| groupBy([user, domain, ip], function=count(as=Total))
| sort(Total)
{% endhighlight %}
```jsx
[
  {
    "ip": "192.168.1.157",
    "domain": "pam",
    "Total": "30",
    "user": "root"
  },
  {
    "ip": "192.168.1.157",
    "domain": "open",
    "Total": "13",
    "user": "root"
  },
  {
    "ip": "192.168.1.157",
    "domain": "pve",
    "Total": "9",
    "user": "admin"
  },
  {
    "ip": "192.168.1.157",
    "domain": "pve",
    "Total": "5",
    "user": "root"
  }
]
```

#### Detection Analytics

**Identify the volume of each key property per source**

**CQL**
{% highlight js %}
// extract key fields
regex(field=@rawstring, regex="rhost=(?:::ffff:)?(?<ip>.*?)\s+user=(?<user>[^@\s]+)(?:@(?<domain>[a-zA-Z0-9.\-]+))?")
// no realm means local host auth was tried
| case{
  domain != *
  | domain := "pam"; *
  
}
// aggregate by source
| groupBy([ip], function=[
                          // count key fields
                          count(as=Total), 
                          count(domain, distinct=true, as=TotalDomains), 
                          count(user, distinct=true, as=TotalUsers),
                          // find start and end of activity
                          max(@timestamp, as=end), 
                          min(@timestamp, as=start)])

// calculate new values
| delta := end - start
| round("delta")
| formatDuration("delta")
{% endhighlight %}

**KQL**

{% highlight js %}
| extend key_fields = extract_all(@"rhost=(?:::ffff:)?(?P<ip>.*?)\s+user=(?P<user>[^@\s]+)(?:@(?P<domain>[a-zA-Z0-9.\-]+))?", rawstring)
| extend 
    ip = tostring(key_fields[0][0]),
    user = tostring(key_fields[0][1]),
    domain = tostring(key_fields[0][2])
| summarize 
            total = count(), 
            dcount(user), 
            dcount(domain), 
            max(TimeGenerated),
            min(TimeGenerated) by ip
| extend delta = max_TimeGenerated - min_TimeGenerate
{% endhighlight %}

Once an adversary has GUI access to a Proxmox environment their actions are only traceable through these API audit logs. Additionally the Proxmox interface also offers several options for a new shell to be spawned. Creating a shell is logged in the aforementioned API audit logs however it is not afforded any terminal logging forcing us to utilise auditd to trace any activity.


### GUI Shell Logs:

Journalctl provides an auditable trace of which shells were spawned by the GUI under the pvedaemon.service unit.

**VNC shell**

```jsx
<root@pam> starting task UPID:pve:00001508:00026749:6A33B297:vncshell::root@pam:

starting vnc proxy UPID:pve:00001508:00026749:6A33B297:vncshell::root@pam:

launch command: /usr/bin/vncterm -rfbport 5900 -timeout 10 -authpath /nodes/pve -perm Sys.Console -notls -listen localhost -c /bin/login -f root

launch command: /usr/bin/vncterm -rfbport 5900 -timeout 10 -authpath /nodes/pve -perm Sys.Console -notls -listen localhost -c /bin/login -f root
```

**Spice Shell**

```jsx
<root@pam> starting task UPID:pve:000017F7:0002C7B3:6A33B38E:spiceshell::root@pam:

starting spiceterm UPID:pve:000017F7:0002C7B3:6A33B38E:spiceshell::root@pam: - Shell on 'pve'

launch command: /usr/bin/spiceterm --port 61000 --addr localhost --timeout 40 --authpath /nodes/pve --permissions Sys.Console --keymap en-gb -- /bin/login -f root

```

**xterm.js (default shell option)**

```jsx
<root@pam> starting task UPID:pve:00001A2C:0003190A:6A33B45E:vncshell::root@pam:

starting termproxy UPID:pve:00001A2C:0003190A:6A33B45E:vncshell::root@pam:

```

**View the full log here:**
[sim_proxmox_guishell_rawlog.json]({{ site.url }}\assets\proxmox_death\sim_proxmox_guishell_rawlog.json)


In our example once an adversary has spawned a new shell via the GUI they begin executing shell commands to explore the pve nodes file system with the aim to identify where Guest VM backups are stored.

Guest VM components exist logically in a few key areas of each PVE node. Primarily the Guest VM sits as a logical volume on the selected disk. This is represented under /dev/pts/ and /dev/pve/. Additionally backups created for each Guest VM and any miscellaneous backup logs are stored in the directory ‘/var/lib/vz/dump/’.

Adversaries can easily enumerate these storage locations using the following command

```jsx
find /var/lib/vz/dump/ -type f -name "*zst*"
```

Find: A LOLBIN kept on all debian hosts.

```jsx
[
  {
    "first_event": "2026-06-18 09:09:24.486",
    "Vendor.audit_type": "EXECVE",
    "Vendor.audit_content": "argc=6 a0=\"find\" a1=\"/var/lib/vz/dump/\" a2=\"-type\" a3=\"f\" a4=\"-name\" a5=\"*zst*\""
  },
  {
    "first_event": "2026-06-18 09:09:24.486",
    "Vendor.audit_type": "PATH",
    "Vendor.audit_content": "item=0 name=\"/usr/bin/find\" inode=260723 dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
  },
  {
    "first_event": "2026-06-18 09:09:24.486",
    "Vendor.audit_type": "PATH",
    "Vendor.audit_content": "item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=264121 dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
  },
  {
    "first_event": "2026-06-18 09:09:24.486",
    "Vendor.audit_type": "PROCTITLE",
    "Vendor.audit_content": "find\u0000/var/lib/vz/dump/\u0000-type\u0000f\u0000-name\u0000*zst*"
  },
  {
    "first_event": "2026-06-18 09:09:24.486",
    "Vendor.audit_type": "SYSCALL",
    "Vendor.audit_content": "arch=c000003e syscall=59 success=yes exit=0 a0=5edc57afb490 a1=5edc57f51760 a2=5edc57f2bcc0 a3=8 items=2 ppid=7764 pid=7882 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm=\"find\" exe=\"/usr/bin/find\" subj=unconfined key=\"exec\""
  }
]
```

lvdisplay: LOLbin that displays volume information

```jsx
[
  {
    "first_event": "2026-06-18 09:23:18.143",
    "Vendor.audit_type": "EXECVE",
    "Vendor.audit_content": "argc=1 a0=\"lvdisplay\""
  },
  {
    "first_event": "2026-06-18 09:23:18.143",
    "Vendor.audit_type": "PATH",
    "Vendor.audit_content": "item=0 name=\"/usr/sbin/lvdisplay\" inode=265377 dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
  },
  {
    "first_event": "2026-06-18 09:23:18.143",
    "Vendor.audit_type": "PATH",
    "Vendor.audit_content": "item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=264121 dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
  },
  {
    "first_event": "2026-06-18 09:23:18.143",
    "Vendor.audit_type": "PROCTITLE",
    "Vendor.audit_content": "lvdisplay"
  },
  {
    "first_event": "2026-06-18 09:23:18.143",
    "Vendor.audit_type": "SYSCALL",
    "Vendor.audit_content": "arch=c000003e syscall=59 success=yes exit=0 a0=5edc57adb980 a1=5edc57f504c0 a2=5edc57f2bcc0 a3=8 items=2 ppid=7764 pid=10088 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm=\"lvdisplay\" exe=\"/usr/sbin/lvm\" subj=unconfined key=\"exec\""
  }
]
```


#### Detection Analytics

**Identify storage and volume enumeration activity**

**CQL**
{% highlight js %}
| case {
  
  // directory used in cmdline
  audit_type = PROCTITLE
  | process.command_line = /\/var\/lib\/vz\/dump\//i
  | direct_dir_access := @timestamp;

  // volume enumeration
  dataset = auditd.syscall
  | Vendor.comm = lvdisplay
  | lvdisplay := @timestamp;

  // pve shell enumeration
  audit_type = EXECVE
  |  process.command_line = /\/usr\/bin\/pvesh get/i
  | pve_shell_enum := @timestamp;
  
  //QEMU enumeration
  audit_type = EXECVE
  |  process.command_line = /\/usr\/sbin\/qm list/i
  | qemu_enum := @timestamp;

  //pve storage manager storage content
  audit_type = EXECVE
  |  process.command_line = /\/usr\/sbin\/pvesm list/i
  | storage_content := @timestamp;

  //pve storage manager volume paths
  audit_type = EXECVE
  |  process.command_line = /\/usr\/sbin\/pvesm path/i
  | volume_paths:= @timestamp;

  
}
| groupBy([@collect.host], function=[
                                      min(direct_dir_access, as=min_direct_dir_access),
                                      min(lvdisplay, as=min_lvdisplay),
                                      min(pve_shell_enum, as=min_pve_shell_enum),
                                      min(qemu_enum, as=min_qemu_enum),
                                      min(storage_content, as=min_storage_content),
                                      min(volume_paths, as=min_volume_paths),
                                      collect(process.command_line, Vendor.comm)
  
  
                          ])
{% endhighlight %}