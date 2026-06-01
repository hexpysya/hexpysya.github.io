---
title: "Splunk-DCSync and DCShadow"
date: 2026-05-13
draft: false
summary: "Research covering DCSync and DCShadow detection - two advanced techniques abusing Active Directory replication permissions to extract password hashes and inject unauthorized AD changes without standard security logs, with Splunk queries targeting Event IDs 4662 and 4742."
tags:
  - Splunk
  - Active Directory
  - DCSync
  - DCShadow
  - Persistence
platform: DFIR
---

### <span style="color:red">DCSync</span>

#### How It Works

DCSync exploits the *DS-Replication-Get-Changes* permission that domain controllers use to synchronize AD data. By impersonating a DC using Mimikatz *lsadump::dcsync*, an attacker sends *DRSGetNCChanges* RPC calls to a legitimate DC and requests replication data for specific objects - including password hashes for the *KRBTGT* account and domain administrators. The DC responds as if it were talking to a peer DC, returning the hashes without any authentication failure.

The primary advantage over *lsass.exe* dumping is that DCSync never touches the target machine's memory - the attacker pulls hashes remotely from wherever they have admin credentials.

Attack steps:
1. Gain membership in Administrators, Domain Admins, or Enterprise Admins
2. Run Mimikatz *lsadump::dcsync /domain:corp /user:krbtgt*
3. Use the obtained hashes for Golden Ticket attacks or PtH

#### Detection Logic

Event ID 4662 (An operation was performed on an object) is generated when the replication permission is exercised. This requires manually enabling an audit policy - **not enabled by default**:

```
Computer Configuration > Windows Settings > Security Settings >
Advanced Audit Policy Configuration > DS Access > Audit Directory Service Access
```

The event contains GUIDs rather than human-readable names. The GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` corresponds to *DS-Replication-Get-Changes*. Filtering on "Replicating Directory Changes" in the Message field catches it without hardcoding GUIDs:

```
index=main EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

Any non-DC account appearing in the results should be investigated immediately.

![DCSync - Event ID 4662 detection](image-3.png)

### <span style="color:red">DCShadow</span>

#### How It Works

DCShadow is more destructive than DCSync - instead of reading from a DC, the attacker registers a **rogue domain controller** and pushes unauthorized changes into AD. Those changes then replicate to all legitimate DCs through the standard replication mechanism, making them appear as normal replication traffic rather than direct LDAP writes.

The attack requires two concurrent Mimikatz processes: one running as SYSTEM to register the rogue DC (creating a new *nTDSDSA* object and adding a Global Catalog SPN to the computer account), and one running as Domain Admin to trigger replication. After the push completes, the rogue DC unregisters itself - leaving minimal trace.

Typical changes pushed via DCShadow include adding users to Domain Admins, modifying *SIDHistory*, or changing *AdminSDHolder* ACLs.

Attack steps:
1. Obtain SYSTEM and Domain Admin access on a domain-joined machine
2. Register a rogue DC by creating *nTDSDSA* object and adding `GC/` SPN to the computer object
3. Use Mimikatz *lsadump::dcshadow /push* to push changes to AD
4. Rogue DC unregisters - changes have already replicated

#### Detection Logic

Event ID 4742 (Computer account was changed) logs modifications to computer objects including *ServicePrincipalName* changes. DCShadow must add a `GC/` (Global Catalog) SPN to register the rogue DC - this SPN addition is the detectable artifact. The following query extracts `GC/` SPNs from computer account change events:

```
index=main earliest=1690623888 latest=1690623890 EventCode=4742
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```

Any `GC/` SPN appearing on a non-DC computer account is highly suspicious. Legitimate DC registrations are infrequent and should correspond to known infrastructure changes.

![DCShadow - Event ID 4742 detection](image-4.png)