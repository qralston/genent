#! /usr/bin/python3

from ldif import LDIFParser
import base64
import logging
import optparse
import grp
import sys

# Global variables.
DEBUG = False
PROG = 'getent'
QUIET = False
VERBOSE = False
VERSION = 'master'

# Additional global variables.
input_file = ''
output_file = ''
max_group_recursion_level = 32

class objectSID:
    'Operate on a binary-encoded Windows SID object'

    def __init__(self, remainder):
#       remainder = base64.b64decode(base64_sid, altchars=None, validate=True)
        if len(remainder) < 8:
            raise TypeError("objectSid %s is too short to be valid" % sid)
        self.__revision = int(remainder[0])
        count = int(remainder[1])
        self.__authority = (int(remainder[2])<<40) + (int(remainder[3])<<32) + (int(remainder[4])<<24) + (int(remainder[5])<<16) + (int(remainder[6])<<8) + (int(remainder[7]))
        remainder = remainder[8:]
        if self.__revision != 1:
            raise TypeError("objectSid %s revision is not 1" % base64_sid)
        if count * 4 != len(remainder):
            raise TypeError("length %u of objectSid does not agree with actual length" % count)
        if count < 2:
            raise TypeError("sorry; I don't know how to deal with objectSid %s of length %u" % (base64_sid, count))
        self.__issuer = []
        while count > 1:
            self.__issuer.append(int(remainder[0]) + (int(remainder[1])<<8) + (int(remainder[2])<<16) + (int(remainder[3])<<24))
            count -= 1
            remainder = remainder[4:]
        self.__rid = int(remainder[0]) + (int(remainder[1])<<8) + (int(remainder[2])<<16) + (int(remainder[3])<<24)

    @property
    def revision(self):
        return self.__revision

    @property
    def authority(self):
        return self.__authority

    @property
    def issuer(self):
        return '-'.join(map(str,self.__issuer))

    @property
    def rid(self):
        return self.__rid

    @property
    def to_string(self):
        return "S-%u-%u-%s-%u" % (self.__revision, self.__authority, '-'.join(map(str,self.__issuer)), self.__rid)

class MyLDIF(LDIFParser):

    # We use this attribute to accumulate the LDIF objects we have parsed.
    _objects = {}

    class MyLDIF(LDIFParser):
        def __init__(
                self,
                input_file,
                ignored_attr_types=None,
                max_entries=0,
                process_url_schemes=None,
                line_sep='\n'
        ):
            LDIFParser.__init__(self,input)

    # The parse() method calls the handle() method once for each LDIF object it
    # processes, so this is where we do all of our work.

    def handle(self, dn, entry):

        object_sid = ''
        cn = ''

        seen_sam_account_names = {}

        is_user = False
        is_computer = False
        is_dc = False
        is_group = False

        required_attributes = ['objectClass', 'cn', 'sAMAccountName', 'objectSid']

        log.debug('handling dn=%s', dn)

        # We need to perform numerous sanity-checks on the LDIF entry.  The
        # first test is whether the entry has all of the attributes we need it
        # to have.

        for attribute in required_attributes:
            if not attribute in entry:
                log.warning('entry with dn=%s is missing require %s attribute; skipping', dn, attribute)
                return 1

        # The next test is whether the entry is for a user or group.

        if b'user' in entry['objectClass']:
            is_user = True

        if b'group' in entry['objectClass']:
            is_group = True

        if is_user and is_group:
            log.warning('entry dn=%s is both a user and group; skipping', dn)
            return 1

        if not (is_user or is_group):
            log.warning('entry dn=%s is neither a user nor group; skipping', dn)
            return 1

        # If we are asked to synthesize passwd(5) entries, the pw_gid we output
        # will vary depending on whether this object is a regular user, a
        # computer, or a domain controller.  So we need to gather that
        # information.

        if is_user:

            if b'computer' in entry['objectClass']:
                is_computer = True

            if 'OU=Domain Controllers' in dn.split(','):
                is_dc = True

        # The sAMAccountName attribute must be a list, must have only one
        # element in it, and that element must not contain a colon.

        if not isinstance(entry['sAMAccountName'], list):
            log.warning('entry dn=%s sAMAccountName attribute is not a list; skipping', dn)
            return 1

        if len(entry['sAMAccountName']) != 1:
            log.warning('entry dn=%s has multiple sAMAccountName attributes; skipping', dn)
            return 1

        sam_account_name = entry['sAMAccountName'][0].decode()
        sam_account_name_lc = sam_account_name.lower()

        if ':' in sam_account_name:
            log.warning('entry dn=%s sAMAccountName attribute %s contains ":"; skipping', dn, entry['sAMAccountName'][0].decode())
            return 1
        else:
            log.debug('entry dn=%s: sAMAccountName=%s', dn, sam_account_name)

        # We must not have already seen the sAMAccountName this object has on
        # some other object.
        #
        # Note that we perform this comparison against the lowercased
        # sAMAccountName value, as we lowercase it by default when we output
        # it.

        if sam_account_name_lc in seen_sam_account_names:
            log.warning('entry dn=%s sAMAccountName attribute duplicates sAMAccountName for dn=%s', dn, seen_sam_account_names[sam_account_name_lc])
            return 1
        else:
            seen_sam_account_names[sam_account_name_lc] = 1

        # The objectSid attribute must be a list, and must have only one
        # element in it.

        if not isinstance(entry['objectSid'], list):
            log.warning('entry dn=%s objectSid attribute is not a list; skipping', dn)
            return 1
        elif len(entry['objectSid']) != 1:
            log.warning('entry dn=%s has multiple objectSid attributes; skipping', dn)
            return 1
        else:
            object_sid = entry['objectSid'][0]
            log.debug('entry dn=%s: objectSid=%s', dn, (base64.b64encode(object_sid)).decode())

        # The cn attribute must exist, it must be a list, it must have only one
        # element in it, and that element must not contain a colon.

        if not 'cn' in entry:
            log.warning('entry dn=%s lacks cn attribute; skipping', dn)
            return 1
        elif not isinstance(entry['cn'], list):
            log.warning('entry dn=%s cn attribute is not a list; skipping', dn)
            return 1
        elif len(entry['cn']) != 1:
            log.warning('entry dn=%s has multiple cn attributes; skipping', dn)
            return 1
        else:
            cn = entry['cn'][0].decode()
            if ':' in cn:
                log.warning('entry dn=%s cn attribute %s contains ":"; skipping', dn, cn)
                return 1
            else:
                log.debug('entry dn=%s: cn=%s', dn, cn)

        # If we have already seen an object that has the same dn as this
        # object, skip this one.

        if dn in self._objects:
            log.warning('already encountered object with dn=%s; skipping dn=%s', self._objects[dn], dn)
            return 1

        # If we made it to here, all sanity checks passed, so add this entry.

        self._objects[dn] = {
            'objectSid': object_sid,
            'sAMAccountName': sam_account_name,
            'cn': cn,
            'is_user': is_user,
            'is_group': is_group,
            'is_computer': is_computer,
            'is_dc': is_dc,
        }

        # If this object is a group, add any member attributes.

        if is_group and 'member' in entry:
            self._objects[dn]['member'] = []
            for member in entry['member']:
                self._objects[dn]['member'].append(member.decode())

    # A simple method to return our objects.
    def objects(self):
        return self._objects

def expand_members(sam_account_names, group_to_expand, objects, dn_list, recurse_level):

    # Active Directory permits groups to contain other groups.  When sssd
    # synthesizes the gr_mem list for a group, it recursively expands any
    # groups it finds.  We will do the same.
    #
    # In order to prevent an infinite recursion loop, we will set a maximum
    # recursion limit.  We could also prevent infinite recursion by remembering
    # which dn objects we've already attempted to expand, but simply
    # implementing a maximum recursion limit is simpler.

    if recurse_level >= max_group_recursion_level:
        log.warning('maximum group recursion level %u reached expanding group %s', max_group_recursion_level, group_to_expand)
        return 1

    for dn in dn_list:
        if dn in objects:
            object = objects[dn]
            if object['is_user']:
                sam_account_names[object['sAMAccountName'].lower()] = 1
            else:
                if 'member' in objects[dn]:
                    expand_members(sam_account_names, group_to_expand, objects, object['member'], recurse_level + 1)

# Initialize a new OptionParser.

p = optparse.OptionParser(description="Generate passwd or group entries from LDIF data.",
                          prog=PROG,
                          usage='%prog [ options ] [ --ldif-file=FILE ] [ --users || --groups ] [ -- ]',
                          version=VERSION)

# Standard options.
p.add_option("-d", "--debug", action="store_true", dest="debug", help="enable debugging messages")
p.add_option("-q", "--quiet", action="store_true", dest="quiet", help="suppress all messages except errors")
p.add_option("-v", "--verbose", action="store_true", dest="verbose", help="enable verbose messages")

# Additional options.
p.add_option("-l", "--ldif-file", action="store", dest="ldif_file", help="the LDIF file to read")
p.add_option("-u", "--users", action="store_true", dest="users", help="emit passwd(5) entries")
p.add_option("-g", "--groups", action="store_true", dest="groups", help="emit group(5) entries")

# Parse options.
opt, args = p.parse_args()

# Initialize logging.
logging.basicConfig(format = '%(name)s: %(levelname)s: %(message)s')
log = logging.getLogger(PROG)
if opt.verbose:
    log.setLevel(logging.INFO)
if opt.debug:
    log.setLevel(logging.DEBUG)
if opt.quiet:
    log.setLevel(logging.ERROR)

# One (and only one) of (--users, --groups) must be specified.

if opt.users and opt.groups:
    log.error('only one of --users or --groups can be specified')
    raise SystemExit(1)

if not (opt.users or opt.groups):
    log.error('one of --users or --groups is required')
    raise SystemExit(1)

# Parse the LDIF records.

if opt.ldif_file:
    log.debug('opening LDIF file %s', opt.ldif_file)
    try:
        with open(opt.users_ldif_file, 'rb') as input_file:
            log.info('parsing input file %s', opt.users_ldif_file)
            parser = MyLDIF(input_file)
            parser.parse()
    except IOError as e:
        log.error('unable to open/process %s: %s', opt.ldif_file, e)
        raise SystemExit(1)
else:
    log.info("parsing stdin")
    parser = MyLDIF(sys.stdin)
    parser.parse()

# Regardless of whether we are emitting passwd(5) or group(5) entries, we need
# to calculate the base id value that sssd is using for the domain.
#
# Because the 'Domain Users' group is a well-known group with a fixed RID of
# 513, we will perform a single getgrnam() call against this group.  If that
# call succeeds, then we can calculate the base, and from that, all of the
# other information we need.

try:
    grent = grp.getgrnam('Domain Users')
except KeyError as e:
    log.error('failed to call getgrnam() for group Domain Users: %s', e)
    raise SystemExit(1)

# And now we have the sssd base for this domain.
base = grent.gr_gid - 513

# If we are synthesizing passwd(5) entries, we need to come up with a
# reasonable pw_gid value.
#
# Roughly speaking, what sssd does is the following:
#
#   * If the object is a domain controller, use the gr_gid value of the
#     'Domain Controllers' group as the pw_gid value.
#
#   * If the object is a computer (but not a domain controller), use the
#     gr_gid value of the 'Domain Computers' group as the pw_gid value.
#
#   * Otherwise, use the gr_gid value of the 'Domain Users' group as the
#     pw_gid value.
#
# We will mimic this behavior.  Because all of these groups have well-known
# RID values, we can calculate their gr_gid values from the base.
#
# We don't use these variables if we're emitting groups, but it's easier to
# define them here unconditionally.

gid_domain_users = base + 513
gid_domain_computers = base + 515
gid_domain_controllers = base + 516

# Both the users and groups case use the issuer.
issuer = ''

# Obtain the objects to enumerate.
objects = parser.objects()

for object in objects:

    # If we're looking for users, skip objects that aren't users; if we're
    # looking for groups, skip objects that aren't groups.

    if opt.users:
        if not objects[object]['is_user']:
            continue
    else:
        if not objects[object]['is_group']:
            continue

    # Parse the objectSid.
    sid = objectSID(objects[object]['objectSid'])

    # An object with an objectSid issuer of '32' is a built-in object.  sssd
    # does not enumerate them, so we won't, either.

    if sid.issuer == '32':
        log.debug('skipping built-in object %s with objectSid issuer %s', object, sid.issuer)
        continue

    # We want to guard against the possibility that the LDIF file we were given
    # contains entries from multiple domains.  To do this, we "lock" to the
    # issuer of the objectSid of the first (non-builtin) object we see.

    if issuer:
        if issuer != sid.issuer:
            log.warning('skipping object %s: objectSid issuer %s differs from first seen issuer %s', object, sid.issuer, issuer)
            continue
    else:
        issuer = sid.issuer

    # Use the lowercase version of the sAMAccountName attribute, the same as sssd.
    sam_account_name_lc = objects[object]['sAMAccountName'].lower()

    if opt.users:

        # We're emitting a user.  What pw_gid value should we use for this
        # user?

        pw_gid = 0
        if objects[object]['is_dc']:
            pw_gid = gid_domain_controllers
        elif objects[object]['is_computer']:
            pw_gid = gid_domain_computers
        else:
            pw_gid = gid_domain_users

        # Print the synthesized passwd(5) entry.
        print("%s:*:%s:%s:%s:/home/%s:/bin/bash" % (sam_account_name_lc, base + sid.rid, pw_gid, objects[object]['cn'], sam_account_name_lc))

    else:

        # If this group object has members (and most group objects do—that's
        # kind of why they are created in the first place), recursively expand
        # those members, up to the maximum recursion limit.

        group_members = {}
        if 'member' in objects[object]:
            expand_members(group_members, object, objects, objects[object]['member'], 0)

        # Print the synthesized group(5) entry.
        print("%s:*:%s:%s" % (sam_account_name_lc, base + sid.rid, ','.join(sorted(group_members.keys()))))

# We're done.
raise SystemExit(0)

#
# Local Variables:
# mode:Python
# fill-column:79
# End:
#
