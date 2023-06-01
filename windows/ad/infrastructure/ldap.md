# LDAP

## Active Directory

Active Directory is a server for LDAP.

[Microsoft Learn - MS-ADTS - LDAP](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/3c5916a9-f1a0-429d-b937-f8fe672d777c)

### ADSI

Active Directory Service Interfaces (ADSI) is a _set of COM interfaces_ used to access the features of directory services from different network providers.

Services can publish themselves in a directory, clients can use the directory to find the services, and both can use the directory to find and manipulate other objects of interest.

[Microsoft Learn - Active Directory Service Interfaces](https://learn.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi)

### LDAP

LDAP is the only system-supplied Active Directory Service Interfaces (ADSI) provider that supports _directory searching_.

[Microsoft Learn - DirectorySearcher Class](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-7.0)

## RootDSE

The logical root of a directory server, whose distinguished name (DN) is the empty string (nameless entry).

As a mechnism for clients of an LDAP server to interact with the server itself, rather than with particular objects contained by the server.

The rootDSE contains the configuration status of the server, it contains attributes that represent the features, capabilities, and extensions provided by the particular server.

> Access to this entry is typically available to _unauthenticated clients_.

## Authentication

Bind operations are used to authenticate clients to the directory server.\
LDAP _bind request_ use either simple or SASL authentication.

### Simple Authentication

The DN of the entry for that account + password in plaintext

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6a5891b8-928e-4b75-a4a5-0e3b77eaca52" %}

### SASL Authentication

Simple authentication and security layer. SASL can use other security layer frameworks like Kerberos for authentication.

{% embed url="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b" %}

### Active Directory

Active Directory supports only simple, SASL and Sicily authentication mechanisms.

See [Microsoft Learn - ADTS - LDAP Supported Authentication Methods](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/e7d814a5-4cb5-4b0d-b408-09d79988b550).

### Password

> Also, while section 6.2 of \[RFC2829] specifies that an object possessing a `userPassword` attribute is a _prerequisite_ to being able to perform a simple bind using that object's credentials, Active Directory _does not_ use the `userPassword` attribute to store the user's password in most cases, and possession of such an attribute is not a prerequisite to performing a simple bind against an object.

Access to the password attribute of an account object is granted only to the account holder, never to anyone else, not even administrators. Only processes with Trusted Computing Base privilege—processes running in the security [_context_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/c-gly) of the LSA—are allowed to read or change password information.

The password attribute of an account object is further protected by a second encryption using a system key.

[https://learn.microsoft.com/en-us/windows/win32/secauthn/account-database](https://learn.microsoft.com/en-us/windows/win32/secauthn/account-database)

### Reference

[\[MS-ADTS\] - Simple Authentication](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/6a5891b8-928e-4b75-a4a5-0e3b77eaca52)\
[\[MS-ADTS\] - SASL Authentication](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b)\
[ldap.com - The LDAP Bind Operation](https://ldap.com/the-ldap-bind-operation/)\
[Microsoft Learn - ADTS - LDAP Authentication](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/baf8d08c-aa1b-40a0-9912-a46145e87878)

## Simple Bind

### Anonymous Authentication

The legitimate use case for this is _LDAP configuration discovery_.

Anonymous authentication allows anyone to fetch the root of a directory server information tree, by the `Get-ADRootDSE` PowerShell command for example.

> `rootDSE` is Defined as the root of the directory data tree on a directory server and provides data about the directory server.

[Microsoft Learn - AD Schema](https://learn.microsoft.com/en-us/windows/win32/adschema/rootdse)\
[RFC 4513 - Anonymous Authentication](https://datatracker.ietf.org/doc/html/rfc4513#section-5.1.1)\
[Microsoft Learn - Get-ADRootDSE](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adrootdse?view=windowsserver2022-ps)\
[Devolutions - Why Active Directory LDAP Unauthenticated Binds Should Be Disabled, and How to Disable It](https://blog.devolutions.net/2021/03/why-active-directory-ldap-unauthenticated-binds-should-be-disabled-and-how-to-do-it/)

### Unauthenticated Authentication

It is possible to [disable LDAP unauthenticated binds starting from Windows server 2019](https://blog.lithnet.io/2018/12/disabling-unauthenticated-binds-in.html).

> Many servers require that if an empty password is provided then an empty DN must also be given now.

[CVE - Related vulnerability](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=unauthenticated+bind)\
[RFC 4513 - Unauthenticated Authentication](https://datatracker.ietf.org/doc/html/rfc4513#section-5.1.2)\
[Lithnet - Disabling Unauthenticated Binds in Active Directory](https://blog.lithnet.io/2018/12/disabling-unauthenticated-binds-in.html)

### Name in Bind Request

Active Directory accepts several forms of name in the name field of the BindRequest.

1. The `DN` of the object
2. The user principal name (UPN) of the object.
   * A value of the [userPrincipalName](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/1f730d08-4f9a-44fc-b638-a5d4a7f19bc3) attribute or
   * The value of the [sAMAccountName](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/56d7e9e4-1505-4d9a-b968-3bf0d6b92809) attribute + `@` +
     * The [DNS name](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_102a36e2-f66f-49e2-bee3-558736b2ecd5) of a [domain](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_b0276eb2-4e65-4cf1-a718-e0920a614aca) in the same [forest](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_fd104241-4fb3-457c-b2c4-e0c18bb20b62) as the object or
     * A value in the [uPNSuffixes](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/caefa19b-346d-4137-8f51-1b317c894027) attribute of the [Partitions container](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_d6b4c198-f9d3-4c49-b0f0-390e07f89af1) in the [config NC](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_54215750-9443-4383-866c-2a95f79f1625) [replica](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_ea02e669-2dda-460c-9992-b12a23caeeac).
3. The [NetBIOS domain name](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_f7f8efcc-c6d5-40f0-9605-c9d99c5a0b92), followed by a backslash (""), followed by the value of the sAMAccountName attribute
4. The [canonical name](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_79ab9d86-0d30-41c3-b7da-153ad41bdfd8) of the object.
5. The value of the [objectGUID](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/937eb5c6-f6b3-4652-a276-5d6bb8979658) attribute
6. The value of the [displayName](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada1/54c39467-cda2-4af1-9454-13b81d30399a) attribute
7. A value of the [servicePrincipalName](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/0b541500-9735-42c1-ab2d-3bfe3bbd3e0f) attribute
8. A value V that, when the MapSPN(V, M) algorithm of [\[MS-DRSR\]](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) section [4.1.4.2.19](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-drsr/77063286-8864-438e-9a71-74e1efac2a9e) is applied to it, corresponds to a value of the servicePrincipalName attribute of the object. M is the value of the [sPNMappings](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/9e3f418e-9b1b-4a31-a88a-71336d811f65) attribute of the [nTDSService](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adsc/5298bde3-5754-4e8a-b5bd-6d1aea26a4b5) object.
9. The value of the [objectSid](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/afac8414-c614-4c6a-b316-41f5978308bd) attribute
10. A value from the [sIDHistory](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-ada3/1c47c6a0-e614-49e5-bef3-f42f71f5eeb2) attribute
11. The canonical name of the object in which the rightmost forward slash (/) is replaced with a newline character (\n).

If the name field of the BindRequest maps to a single object using the attempted name form, the _password on that object_ is checked.

### Reference

[\[MS-ADTS\] - Simple Authentication](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/6a5891b8-928e-4b75-a4a5-0e3b77eaca52)\
[\[MS-ADTS\] - Password Modify Operations](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/3983110d-4d24-4a59-baeb-db5b863a92c6)\
[\[MS-ADTS\] - unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2)\
[\[MS-ADTS\] - userPassword](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/f3adda9f-89e1-4340-a3f2-1f0a6249f1f8)\
[\[MS-SAMR\] - clearTextPassword](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/56a9c9d7-2ec6-4c49-9266-31b9b6ed82fb)

## Search

### Filter

Used to identify entries in search requests.

### Reference

[\[MS-ADTS\] - Abstract Data Model - Read](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/561cd2cb-1c79-4561-bfc2-13c82113d418)

## Tools

### ldapsearch

Here we use `ldapsearch` with anonymous authentication to fetch the roo. of a directory server information tree.

```
$ ldapsearch -H ldap://<IP> -x -s base -b ''
```

### C\#

Build LDAP filter to look for users with SPN values registered for current domain.

```C#
$ldapFilter = "(&(objectClass=user)(objectCategory=user)(servicePrincipalName=*))"
$domain = New-Object System.DirectoryServices.DirectoryEntry
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = $domain
$search.PageSize = 1000
$search.Filter = $ldapFilter
$search.SearchScope = "Subtree"

$results = $search.FindAll()

$Results = foreach ($result in $results)
{
	$result_entry = $result.GetDirectoryEntry()
 
	$result_entry | Select-Object @{
		Name = "Username";  Expression = { $_.sAMAccountName }
	}, @{
		Name = "SPN"; Expression = { $_.servicePrincipalName | Select-Object -First 1 }
	}
}
 
$Results
```

[Netwrix - Use DirectorySearcher to get account with SPN](https://www.netwrix.com/cracking\_kerberos\_tgs\_tickets\_using\_kerberoasting.html)\
[Microsoft Learn - DirectorySearcher Class](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-7.0)

## Usage

### Third-party Service

Third-party applications that integrate with AD usually use LDAP to authenticate users.

These services often store their AD credential in plain text in configuration files.

## Reference

[Netwrix - LDAP Reconnaissance](https://www.netwrix.com/ldap\_reconnaissance\_active\_directory.html)
