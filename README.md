# Introduction

`genent` generates `passwd(5)` and/or `group(5)` entries from LDIF
data, mimicking entries produced by the `ldap_id_mapping = true`
feature of the SSSD Active Directory provider.

This is a work in progress, and contributions are welcome.  (See the
[TODO.md](TODO.md) file.)

# Background

When mapping `passwd(5)` and `group(5)` entries from Active Directory,
if the `ldap_id_mapping` option is set to `true`, the SSSD Active
Directory provider programmatically generates uid/gid values based on
the objectSid attribute of the Active Directory object.  This avoids
needing to set the `uidNumber` and `gidNumber` POSIX attributes on
Active Directory users, and the `gidNumber` POSIX attribute on Active
Directory groups.

However, many third-party systems that integrate with Active Directory
(e.g., network storage appliances) do not support sssd-style Active
Directory objectSid mapping, and instead require the `uidNumber` and
`gidNumber` POSIX attributes.  For sites that have deployed an Active
Directory domain using sssd ID mapping, this is undesirable.

Many of these third-party systems support the ability to feed the
system pre-generated `passwd(5)` and `group(5)` files.  This mechanism
can be used as an alternate to having to set the `uidNumber` and
`gidNumber` POSIX attributes on all Active Directory objects that need
to be visible to the system.

But it is difficult to generate `passwd(5)` and `group(5)` files from
sssd:

1. Enumeration is discouraged in sssd, and may not work reliably.
   (Enumeration may be removed entirely in a future sssd version.)

2. Even if you can pre-generate the usernames and group names you wish
   to enumerate, producing the desired entries by iterating over the
   usernames with `getpwnam(3)` and the group names with `getgrnam(3)`
   is expensive and time-consuming, due to sssd calling `fsync(2)`
   after fetching and caching each object from Active Directory.

In contrast, enumerating Active Directory objects via LDAP-specific
tools (such as `ldapsearch(1)`) is typically orders of magnitudes
faster.  But sssd provides no handy tool to transform the LDIF dump of
an Active Directory object to a `passwd(5)` or `group(5)` entry.

The `genent` program bridges this gap.  At the cost of a single
`getgrnam()` call through the SSSD Active Directory provider, `genent`
produces either `passwd(5)` or `group(5)` entries that match the
entries that the SSSD Active Directory provider produces.  The
resulting `passwd(5)` and `group(5)` files can be loaded onto the
systems that do not support sssd-style ID mapping.

# Operation

First, read the _ID Mapping_ section of the `sssd-ad(5)` man page.

`genent` works by calling `getgrnam(3)` for the `Domain Users` group.
Because the `Domain Users` group is a well-known group with a fixed
RID (513), this permits `genent` to determine the base of the ID range
that sssd has calculated (based on the non-RID component of the SID)
for the domain.

Using this information, `genent` can calculate the uid/gid values for
`passwd(5)` and `group(5)` objects from the `objectSID` attribute of
each object.  Combined with other object attributes (`cn`,
`sAMAccountName`, `member`), `genent` can synthesize `passwd(5)`
and/or `group(5)` entries that are identical to what sssd itself
produces.

Note that `genent` does _not_ read the `sssd.conf(5)` file and does
_not_ know what the settings for the `ldap_idmap_range_min`,
`ldap_idmap_range_max`, `ldap_idmap_range_size`, et. al. settings are.
Thus, `genent` cannot respect `ldap_idmap_range_max`, and can return
entries that are outside of the range set in `sssd.conf(5)`.

(But if this happens, your mapping range is full, which is a bigger
problem, as no new Active Directory objects will be mapped by sssd.)

# Bugs and/or features in progress

See the [TODO.md](TODO.md) file.

# License

`genent` is licensed under the BSD-2-Clause (Simplified BSD; FreeBSD)
license.  See [LICENSE.md](LICENSE.md).
