# Key Distribution Center

The Key Distribution Center (KDC) is implemented as a _domain service_.

KDC uses the Active Directory as its [_account database_](../../auth/overview.md#account-database) and the Global Catalog for directing referrals to KDCs _in other domains_. The [_encryption_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/e-gly) key used in communicating with a user, computer, or service is stored _as an attribute of the account object of that security principal_.

Both Active Directory and KDC run as part of the LSA's process on a _domain controller_.

The KDC is a single process that provides two services: _Authentication and Ticket-Granting service_.

## Authentication Service (AS)

This service issues ticket-granting tickets (TGTs).

## Ticket-Granting Service (TGS)

When clients want access to a computer, they contact the ticket-granting service in the target computer's domain, _present a TGT_, and ask for a ticket to the computer.

## LSA

Both Active Directory and KDC services are started automatically by the domain controller's [_Local Security Authority_](https://learn.microsoft.com/en-us/windows/win32/secgloss/l-gly) (LSA) and run as part of the LSA's process.

## Account `krbtgt`

The [_security principal_](https://learn.microsoft.com/en-us/windows/win32/secgloss/s-gly) name used by the KDC in any domain.

Created automatically when a new domain is created.

### Password

A random password value is assigned to the account automatically by the system during the creation of the domain.

The password for the KDC's account is used to derive a cryptographic key for encrypting and decrypting the TGTs that it issues.

Refer to [Golden Ticket Attack](kdc.md#golden-ticket-attack).

## Golden Ticket Attack

### Tools

* Rubeus
* Mimikatz

### Reference

[Netwrix - Golden Ticket Attack](https://www.netwrix.com/how\_golden\_ticket\_attack\_works.html)

## Reference

[Microsoft Learn - Key Distribution Center](https://learn.microsoft.com/en-us/windows/win32/secauthn/key-distribution-center)
