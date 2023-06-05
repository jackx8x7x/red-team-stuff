# Credential dumping

## Account Database

An account database maintains the [security principals](../overview.md#security-principal) and necessary information for authentication and other purposes.

* an [Active Directory](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-authsod/64781df1-ee20-413e-b8c5-6511c90dbc30#gt\_e467d927-17bf-49c9-98d1-96ddf61ddd90) database maintains the domain security principals, whereas
* the [security account manager (SAM) built-in database](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-authsod/64781df1-ee20-413e-b8c5-6511c90dbc30#gt\_6bb6ffcf-2a22-4989-89ef-6c9937f91b8b) maintains local security principals

### NTDS.dit

File used by AD DS to store [directory data](../../ad/infrastructure/adds/#data-store).

## DCSync Attack

### Overview

Attack uses account with **Replicating Directory Changes All** and **Replicating Directory Changes** privileges with The Directory Replication Service (DRS) Remote Protocol to simulate the behavior of a domain controller (DC) and retrieve password data via [domain replication](../../ad/infrastructure/adds/#replication).

The attacker can conduct a Golden Ticket attack after it gets the [KRBTGT](../../ad/infrastructure/kdc.md#account-krbtgt) hash.

[Netwrix Blog - What Is DCSync Attack?](https://blog.netwrix.com/2021/11/30/what-is-dcsync-an-introduction/)

{% embed url="https://www.netwrix.com/privilege_escalation_using_mimikatz_dcsync.html" %}

### Privileged Accounts

* Members of the Administrators, Domain Admins, Enterprise Admins and Domain Controllers groups have the required privileges by default, and
* it is possible for any user to be granted these privileges.
* In addition, some applications — such as Azure Active Directory Connect — have legitimate need for replication permissions so their service accounts can therefore also be targeted.

### Mimikatz

### Impacket

### Detection/Response

Monitor replication activities between a domain controller and a machine _that is not a domain controller_.

Provides blocking policies that can prevent an account or workstation from executing additional replication

### Related HackTheBox machines

* [Forest](../../../hackthebox/windows/active-directory/forest.md)
