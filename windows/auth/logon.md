---
description: Stuff about logon process.
---

# Logon

## Types of Logon

### Interactive Logon

Using a _local user account_ or a _domain account for:_

* Local logon\
  Logon to a local account grants a user access to Windows resources on the local computer and requires that the user has a user account in the account database maintained by the _Security Account Manager (SAM)_ on the local computer.
* Domain Logon\
  A process that proves the identity of the user to the domain controller, implies eventual user access to local and domain resources, and requires that the user has a user account in an account database, such as Active Directory.

A user can interactively logon to a computer _locally_ or _remotely through_ Terminal Services.

### Network Logon

Used only after interactive logon authentication _has taken place_.

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/bfc67803-2c41-4fde-8519-adace79465f6" %}
Interactive Logon
{% endembed %}

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/131b1590-0c21-46e1-96bf-995a7a2cc461" %}
Network Logon
{% endembed %}

### Abstract

The Windows user logon interface calls the LSA method to securely transfer the user credentials to the Authentication Authority through a _specified authentication protocol_.

<figure><img src="../../.gitbook/assets/圖片.png" alt=""><figcaption><p>Abstract view of interactive domain logon authentication</p></figcaption></figure>

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/5fec2d4d-bb86-4469-b9c3-b1436d8ab681" %}

## Domain Logon

### Kerberos

The domain logon authentication process first tries the Kerberos Authentication Protocol (\[MS-KILE]). If Kerberos fails, the authentication process falls back to the NTLM pass-through mechanism (\[MS-APDS]).

1. First, the client request the TGT from the KDC.
2. Client then requests the service ticket _for the domain-joined computer_.
3. Finally, Client submits the service ticket to verify the user logon information.

See [Kerberos](kerberos.md).

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/2e9de599-e791-4b3d-bb0c-2ffbef5ee665" %}

## References

{% embed url="https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication" %}
Credentials Processes in Windows Authentication
{% endembed %}

{% embed url="https://www.ultimatewindowssecurity.com/securitylog/book/page.aspx?spid=chapter3" %}
www.ultimatewindowssecurity.com - Understanding Authentication and Logon
{% endembed %}
