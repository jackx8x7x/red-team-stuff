# Kerberos

## Introduction

The Kerberos protocol defines how clients interact with a network authentication service.

### Kerberos Tickets

Clients obtain tickets from the [Kerberos Key Distribution Center (KDC)](../ad/infrastructure/kdc.md), and they present these tickets to servers when connections are established. Kerberos tickets represent the client's network credentials.

### GSS API

Applications that use AP exchange messages directly are typically called "kerberized" applications. Most applications use the Generic Security Service Application Program Interface ([GSS-API](overview.md#generic-security-services-gss)) and can even be wrapped by higher-level abstractions such as Simple Authentication and Security Layer (SASL) [\[RFC2222\]](https://go.microsoft.com/fwlink/?LinkId=90322).

### Active Directory

Microsoft extend the Keberos authorization data to provide the server with additional information such as:

* Group membership
* Claims
* Interactive logon information
* Integrity levels

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/27e4854f-1aa5-4f67-8f50-ab745dd85c3a" %}

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962" %}

### Realm

A collection of key distribution centers (KDCs) with a common set of principals, as described in \[RFC4120] section 1.2.

An administrative boundary that uses one set of authentication servers to manage and deploy a single set of unique identifiers.

A realm is a unique logon space.

## Authentication Service

Kerberos V5 is composed of three exchanges:

* The Authentication Service (AS) exchange
* The Ticket-Granting Service (TGS) exchange
* The Client/Server Authentication Protocol (AP) exchange

<figure><img src="../../.gitbook/assets/圖片 (1).png" alt=""><figcaption></figcaption></figure>

The AS exchange and TGS exchange are transported by Kerberos implementations. The AP exchange is passive and relies on an upper-layer application protocol to carry the AP exchange messages.

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13" %}

### AS Exchange

1. **KRB\_AS\_REQ**\
   The client presents its principal name and can present pre-authentication information ([\[RFC4120\] ](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2)sections 5.2.7 and 7.5.2) to request a ticket-granting ticket (TGT) from the KDC (\[RFC4120] section 5.3).
2. **KRB\_AS\_REP**\
   The KDC returns a TGT and a session key the client can use to encrypt and authenticate communication with the KDC _for ticket-granting service (TGS) requests in the TGS exchange_, without reusing the persistent key.

{% embed url="https://datatracker.ietf.org/doc/html/rfc4120#section-3.1" %}

### TGS Exchange

1. **KRB\_TGS\_REQ**\
   The client presents the TGT (\[RFC4120] section 5.3), a [Kerberos authenticator](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579#gt\_4ad68485-ee2b-49ab-a9a7-6c343bce39c6) (\[RFC4120] section 5.5.1), and the [service principal name (SPN)](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579#gt\_547217ca-134f-4b43-b375-f5bca4c16ce4) in the request sent to the KDC for a service ticket (\[RFC4120]  section 5.3) for the server.
2. **KRB\_TGS\_REP**\
   The KDC validates the TGT (\[RFC4120]  section 5.3) and the [authenticator](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579#gt\_e72a2c02-84a2-4ce3-b66f-86f725642dc3) (\[RFC4120] section 5.5.1). If these are valid, the KDC returns a [service ticket](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579#gt\_b4041466-ae24-4fd4-83e4-5dbc4f32aaab) (\[RFC4120] section 5.3) and session key the client can use to encrypt communication with the server.

{% embed url="https://datatracker.ietf.org/doc/html/rfc4120#section-3.3" %}

### AP Exchange

1. **KRB\_AP\_REQ**\
   The client presents the ticket (\[RFC4120] section 5.3) and a new authenticator (\[RFC4120] section 5.5.1). The server will decrypt the ticket, validate the authenticator, and can use any [authorization data](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579#gt\_0eef5aca-03f3-4b09-b79b-cdf7f730ad89) (\[RFC4120] section 5.2.6) contained in the ticket for access control.
2. **KRB\_AP\_REP**\
   Optionally, the client might request that the server verify its own identity. If mutual authentication is requested, the server returns the client's timestamp from the authenticator encrypted with the session key.

## Service Principal Name (SPN)

A unique identifier associates a _service instance_ with a service sign-in account.

{% embed url="https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names" %}

### Format

A SPN must be uniqe in a forest in which it is registered.

```C++
<service class>/<host>:<port>/<service name>
```

{% embed url="https://learn.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns" %}

### Registration

Typically, SPN registration is done by a service installation program running with domain administrator privileges.

{% embed url="https://learn.microsoft.com/en-us/windows/win32/ad/how-a-service-registers-its-spns" %}

## Attacks

### Kerberoasting

[Netwrix - Kerberoasting Attack](https://www.netwrix.com/cracking\_kerberos\_tgs\_tickets\_using\_kerberoasting.html)

### ASREPRoasting
