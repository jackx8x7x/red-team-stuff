# Golden Ticket Attack

## Overview

After the adversary gets the account `krbtgt`'s password hash, it can create a valid Kerberos TGT for any user in the domain and _manipulate that user’s_ [_PAC_](../../auth/kerberos/#privilege-attribute-certificate-pac) _to gain additional privileges._
