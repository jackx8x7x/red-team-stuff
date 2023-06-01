# Forest
## Overview
---
A domain controller created by *HackTheBox* with Exchange server installed in a minimal AD domain.

Can be used to practice the following techniques or tools.
- [ASREPRoasting](../../windows/authentication/kerberos.md#asreproasting)
- [DCSync attack](../../windows/credential/credential_dumping.md#dcsync-attack)
- Bloodhound

## Reconnaissance
---
### Port Scanning
We use `nmap` to figure out what services are running on the target.
```bash
$ nmap -Pn -n -sS -p- -T4 --min-rate 1000 <IP>
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

The results reveal the following informations.
- port 88 tells us that this should be a *domain controller*
- port 389 allows us to fetch informations about target AD domain via LDAP
- port 5985 may allow us access the target using *WinRM* later

### LDAP
It seems that we can fetch information about the target AD domain via [LDAP anonymous authentication](../../windows/ad/infrastructure/ldap.md#anonymous-authentication).
```bash
$ ldapsearch -H ldap://<IP> -x -b 'dc=htb,dc=local'
```

## Initial Access
---
### Alfresco
From the information gather through anonymous LDAP query, we found a *service  account* named `svc-alfresco`.

To expand our knowledge of the technology used by our client, the next thing to do is to find what third-party service, which shall be AD-integrated, related this account.

By google, we found a product named [Alfresco Content Services](https://docs.alfresco.com/content-services/7.0).

From the configuration, we see that the account related to this service has been configured with *Kerberos preauthentication* disable.

![](../../images/forest_alfresco.png)
[Alfresco - Configuration Steps](https://docs.alfresco.com/process-services/latest/config/authenticate/#configuration-steps)

This allows us to get the TGT for this account `svc-alfresco`, and conduct the [*ASREPRoasting*](../../windows/authentication/kerberos.md#asreproasting) attack to retrieve the account password from the TGT.

### ASREPRoasting

### WinRM
We can now login to the target host with credential we get via [WinRM](../../windows/remote/winrm.md).
```bash
$ evil-winrm -i forest.htb -u svc-alfresco -p s3rvice
```

## Reference
---
[Red Team Stuff - DCSync Attack](../../windows/credential/credential_dumping.md#dcsync-attack)  
[Red Team Stuff - WinRM](../../windows/remote/winrm.md)  