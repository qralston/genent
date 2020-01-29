# Be more Pythonic

I typically write in other languages than Python, and `genent` is the
largest complete Python program I’ve written in Python.  As such,
there undoubtably many areas where `genent` could be more Pythonic.

# Add a man page

While the `--help` option should suffice for now, write a real man
page.

# Better detection for missing group expansion?

When synthesizing `passwd(5)` entries, only LDIF data for user objects
is needed, but when synthesizing `group(5)` entries, LDIF data for
both group _and_ user objects is needed in order to populate the
`gr_mem` list (the members of the group).

We would like to detect when `--groups` is used without supplying LDIF
data for user objects, but this is difficult, as groups can contain
objects that are neither other groups nor user objects (Exchange
public folders, for example).  Since we currently only load user and
group objects from the LDIF data we read, this means any attempt to
generate warnings if we are unable to locate an object when expanding
a group membership will generate false-positives for objects that are
neither users nor groups and would not appear in the group membership
(as returned by sssd) anyway.

Probably the only realistic way to solve this is to load _every_ LDIF
object we parse, regardless of its `objectClass`, and distinguish
among user objects, group objects, and other objects.

# Add a `--verify` option

The idea behind this option is to double-check that we are
synthesizing the same entries that sssd produces.

For the simplest implementation, for every entry we synthesize, we can
call `getpwnam(3)` (for a user) or `getgrnam(3)` (for a group) and
verify that all fields match.  (For the `gr_mem` list of groups, we
will need to be intelligent about the comparison, as we alphabetize
the list of usernames in the `gr_mem` fields we produce, but sssd does
not.)

Since verifying every single entry will be slow, a more complex
implementation could make `--verify` not a boolean flag but one that
accepts a number (e.g. `--verify _N_`), which means to verify _N_% of
the entries synthesized.

# More intelligent `pw_dir` generation

When synthesizing `passwd(5)` entries, we should provide options to
mimic sssd’s `override_homedir` and/or `fallback_homedir`
configuration options, including the sssd AD provider’s behavior of
parsing the `loginShell` attribute (if present) of user objects.

# More intelligent `pw_shell` generation

When synthesizing `passwd(5)` entries, We should provide an option to
mimic sssd’s `default_shell` configuration option, including the sssd
AD provider’s behavior of parsing the `loginShell` attribute (if
present) of user objects.
