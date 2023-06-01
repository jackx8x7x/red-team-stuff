# AD DS

## Overview

A directory service stores and publishes information about Active Directory objects such as users, groups, computers, domains, organizational units, and security policies for use by users and administrators in a hierarchical structure.

AD DS is a deployment of Active Directory.

Implemented as `Ntdsa.dll` running in the `Lsass` process.

### Domain Controller

Domain controllers in a domain participate in replication and contain a complete copy of all directory information for their domain.

The DCs interoperate as peers to ensure that a local change to an object replicates correctly across DCs.

## Data Store

The Active Directory directory service uses a data store for all directory information. This data store is often referred to as the _directory_.

The directory is stored on domain controllers and can be accessed by network applications or services.

### File `Ntds.dit`

Directory data is stored in the `Ntds.dit` file on the domain controller.

[Microsoft Learn - Directory data store](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc736627\(v=ws.10\))

## Replication

Changes made to the directory on one domain controller are replicated to other domain controllers in the domain, domain tree, or forest.

Private directory data is stored securely, and public directory data is stored on a _shared system volume_ where it can be replicated to other domain controllers in the domain.

### Site

Sites, defined as groups of well-connected computers, determine how directory data is replicated.

Active Directory relies on the concept of sites within where Active Directory replicates directory information more frequently to help keep replication efficient.

The domain controllers in other sites also receive the changes, but less frequently.

[Microsoft Learn - Sites overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc782048\(v=ws.10\))

### Partition

Changes to each directory partition are replicated to all other domain controllers that hold a copy of that partition.

### Reference

[Microsoft Learn - Replication Overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc737144\(v=ws.10\))

## Partition

Directory partitions are also known as _naming contexts_.

A directory partition is a contiguous portion of the overall directory that has independent replication scope and scheduling data.

https://learn.microsoft.com/en-us/windows/win32/ad/naming-contexts-and-partitions

### Default Partitions

Data is stored on each domain controller in the directory store, which is divided logically into four distinct directory partition types to store and copy different types of data:

* domain
* configuration
* schema
* application data.

All domain controllers within a particular domain hold a replica of the domain partition for their domain.

All domain controllers within a forest hold a replica of _the schema and configuration partitions for that forest_.

Application directory partitions hold directory data specific to a particular application and can be stored by domain controllers belonging to different domains.

## Management

### Ntdsutil

[Microsoft Learn - Ntdsutil](https://learn.microsoft.com/en-us/previous-versions/orphan-topics/ws.10/cc755915\(v=ws.10\)?redirectedfrom=MSDN)\
[LOLBAS - Ntdsutil.exe](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Ntdsutil/)

## Security

Security is integrated with Active Directory through

* logon authentication
* access control to objects in the directory.

### Access Control

An object or its attributes may not be visible to a requester if the requester is not granted the necessary rights.

[Active Directory](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_e467d927-17bf-49c9-98d1-96ddf61ddd90) provides access control in the form of [access control lists (ACLs)](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_9f92aa05-dd0a-45f2-88d6-89f1fb654395) on [directory](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_49ce3946-04d2-4cc9-9350-ebcd952b9ab9) [objects](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt\_8bb43a65-7a8c-4585-a7ed-23044772f8ca).

https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/8271b44d-a755-4872-a762-1ac57152099d

## Reference

[Microsoft Learn - Active Directory Domain Services Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)\
[Microsoft Learn - Understanding Active Directory](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781408\(v=ws.10\))
