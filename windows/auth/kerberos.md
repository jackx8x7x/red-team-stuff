# Kerberos

## Introduction

The Kerberos protocol defines how clients interact with a network authentication service.

### Kerberos Tickets

Clients obtain tickets from the [Kerberos Key Distribution Center (KDC)](../ad/infrastructure/kdc.md), and they present these tickets to servers when connections are established. Kerberos tickets represent the client's network credentials.

### Windows Negotiate

The applications use the _Negotiate security package_ instead of accessing the Kerberos security package directly.

Currently, the Negotiate security package selects between Kerberos and NTLM. Negotiate selects Kerberos unless it cannot be used by one of the systems involved in the authentication.

To allow Negotiate to select the Kerberos security provider, the client app must provide one of the following:

* A service principal name (SPN).
* A user principal name (UPN).
* A NetBIOS account name as the target name.

{% embed url="https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate" %}

{% embed url="https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos" %}

## Authentication

### AS-REQ

## Attacks

### Kerberoasting

[Netwrix - Kerberoasting Attack](https://www.netwrix.com/cracking\_kerberos\_tgs\_tickets\_using\_kerberoasting.html)

### ASREPRoasting
