---
title: "Splunk-AWSRaid"
date: 2026-04-15
draft: false
summary: "An attacker conducted a brute-force attack to compromise the helpdesk.luke account, performed reconnaissance from various VPN IPs, exfiltrated sensitive data including customer backups and secrets, modified bucket permissions, and established persistence by creating an admin backdoor account."
tags:
  - Splunk
  - SOC
  - SIEM
  - Log Analysis
  - DFIR
  - AWS
  - CloudTrail
  - S3
  - IAM
  - BruteForce
---

### <span class="hl">TL;DR</span>

Starting at **09:53:27**, an attacker operating from `185.192.70.84` executed a targeted brute-force attack against AWS accounts, successfully compromising `helpdesk.luke` within 33 seconds. The attacker immediately began environment reconnaissance from rotating IPs within the `185.192.70.0/24` subnet. Using the compromised access, they exfiltrated multiple high-value objects from S3 buckets, including `CustomerData_Backup_2023-11-01.zip` and `secrets_vault_dump.bak`. To facilitate broader access, they disabled `PublicAccessBlock` configurations on the `backup-and-restore` bucket. Finally, rotating to IP `185.192.70.78`, the attacker established persistence by creating a new IAM user, `marketing.mark`, and escalated privileges by adding this backdoor account to the `Admins` group.

### <span style="color:red">Initial Access</span>
#### Brute Force
I received an incident report regarding potential unauthorized access and data exfiltration within our AWS environment. I started the investigation with a broad CloudTrail query to look for brute-force activity.

```splunk
index = * sourcetype="aws:cloudtrail" eventName = "ConsoleLogin" 
| table _time, userIdentity.userName, responseElements.ConsoleLogin,sourceIPAddress
```
![alt text](image.png)

The logs revealed a rapid sequence of 8 failed login attempts originating from `185.192.70.84` within just 33 seconds. At **2023-11-02 09:54:04**, the brute-force attack succeeded, and the attacker gained access to the `helpdesk.luke` account. I checked the originating IP and confirmed it belongs to a known UK-based VPN provider, indicating the attacker is attempting to mask their true location.

![alt text](image-1.png)

### <span style="color:red">Discovery and Reconnaissance</span>

Immediately following the successful login, the attacker began executing discovery commands (e.g., `DescribeRegions`, `ListIndexes`, `ListBuckets`, `GetBucketPolicyStatus`) to map out the AWS environment and identify target resources.

![alt text](image-2.png)

During this recon phase, the attacker began rotating their source IPs across the `185.192.70.0/24` subnet, leveraging their VPN provider's infrastructure to distribute the activity.

### <span style="color:red">Exiltration</span>
#### S3 bucket
I focused my search on S3 access logs for the compromised `helpdesk.luke` account to identify what data the attacker accessed.

```splunk
index=* sourcetype="aws:cloudtrail" *helpdesk* AND (eventName IN (GetObject, PutObject)) | sort _time
```

![alt text](image-3.png)

The logs confirmed significant data exfiltration. The attacker issued multiple `GetObject` requests, successfully downloading several highly sensitive and critical files from various S3 buckets:
* **secrets_vault_dump.bak** (from backup-and-restore98825501)
* **CustomerData_Backup_2023-11-01.zip** (from customer-data-backup57893984)
* **Contract_Agreement.pdf** (from legal-docs45020393)
* **prototype.obj** (from research-project-files23411723)

#### PublicAccessBlock

At **09:58**, the attacker modifies the security posture of the `backup-and-restore98825501` bucket.

```
requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false 
requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false   
requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false    
requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
```

![alt text](image-4.png)

By setting all these parameters to `false`, the attacker effectively disabled the S3 Block Public Access protections, making the bucket public and allowing unauthenticated internet access to its contents.

### <span style="color:red">Persistence and Privilege Escalation</span>
#### New User
To maintain access even if the `helpdesk.luke` account password was reset, the attacker established a backdoor. Rotating to a new IP address, 185.192.70.78, they created a new IAM user named `marketing.mark`.

![alt text](image-5.png)
#### Admins group
Following the account creation, the attacker added `marketing.mark` to the `Admins` IAM group, granting their backdoor account full administrative privileges over the AWS environment.

![alt text](image-6.png)

### <span class="hl">IOCs</span>

| Type | Value | Description |
|------|-------|-------------|
| IP | `185.192.70.84` | Initial brute-force source (VPN Consumer London) |
| IP Subnet | `185.192.70.0/24` | Rotating VPN infrastructure used for reconnaissance |
| IP | `185.192.70.78` | Source IP used for creating the backdoor account |
| Account | `helpdesk.luke` | Initial compromised account |
| Account | `marketing.mark` | Backdoor IAM account created by the attacker |
| Group | `Admins` | IAM group abused for privilege escalation |
| Bucket | `backup-and-restore98825501` | S3 bucket modified to allow public access |
| File | `secrets_vault_dump.bak` | Exfiltrated high-value data |
| File | `CustomerData_Backup_2023-11-01.zip` | Exfiltrated high-value data |

### <span class="hl">Attack Timeline</span>

{{< mermaid >}}
%%{init: {'theme': 'base', 'themeVariables': { 'background': '#ffffff', 'mainBkg': '#ffffff', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#ffffff', 'clusterBorder': '#333333'}}}%%
graph TD
    classDef default fill:#f9f9f9,stroke:#333,stroke-width:1px,color:#000;
    classDef access fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#000;
    classDef recon fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef exfil fill:#fce4ec,stroke:#880e4f,stroke-width:2px,color:#000;
    classDef evasion fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000;
    classDef persist fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#000;

    A([VPN IP - 185.192.70.84]):::default --> B[09:53:27 - Brute-force attack begins]:::access
    B --> C[09:54:04 - Successful login to helpdesk.luke]:::access
    
    subgraph Discovery [Discovery]
        C --> D[09:54-09:55 - Reconnaissance<br/>DescribeRegions, ListBuckets, etc.<br/>IPs rotating via 185.192.70.0/24]:::recon
    end

    subgraph Collection [Data Exfiltration]
        D --> E[09:55-09:57 - GetObject execution<br/>Exfiltration of CustomerData_Backup.zip,<br/>secrets_vault_dump.bak, and others]:::exfil
    end

    subgraph Defense [Defense Evasion]
        E --> F[09:58:01 - PutBucketPublicAccessBlock<br/>backup-and-restore bucket made public]:::evasion
    end

    subgraph Persistence [Persistence & PrivEsc]
        F --> G[09:59:33 - Creation of backdoor IAM user<br/>marketing.mark from IP 185.192.70.78]:::persist
        G --> H[09:59 - marketing.mark added to Admins group]:::persist
    end
{{< /mermaid >}}