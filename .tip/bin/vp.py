#!/usr/bin/python3

"""
vp.py - Patch verifier and massager tool
"""


# TODO (and potential ideas):
#
# a8: switch to logging module maybe:
# https://docs.python.org/3/howto/logging.html#logging-basic-tutorial

import re
import sys
import time
import os.path
import inspect
import argparse
import datetime
import traceback
import collections          # OrderedDict
import configparser

# Import the email modules we'll need
from email import policy, utils
from email.parser import BytesParser

import enchant              # spell checker
import unidiff

from git import Repo

# verbosity levels
# 0 - none
# 1 - info
# 2 - dbg
#
verbose = 0
tmp_dir = None
sob = None

### generic helpers

def __func__():
    return inspect.stack()[2][3]

def err(s):
    global args

    sys.stderr.write(("%s: Error: %s\n" % (__func__(), s, )))

    if not args.force:
        sys.exit(1)

def warn(cond, s):
    if cond:
        print(("%s: Warning: %s" % (__func__(), s, )))

def __verbose_helper(s, v, v_lvl):
    if v < v_lvl:
        return

    # caller is the second function up the frame
    f = inspect.stack()[2][3]

    print(("%s(): %s" % (f, s, )))

def dbg(s):
    global verbose

    __verbose_helper(s, verbose, 2)

def info(s):
    global verbose

    __verbose_helper(s, verbose, 1)

def print_exception():
    stuff = sys.exc_info()

    print("Exception: ", stuff[1])
    traceback.print_tb(stuff[2])


#
### specific helpers

def rfc2822_now():
    now_datetime = datetime.datetime.now()
    now_tuple    = now_datetime.timetuple()

    # formatdate wants a float in seconds since the beginning of the epoch
    return utils.formatdate(time.mktime(now_tuple))

# remove brackets which are left overs from splitting a line into words
def strip_brackets(w):
    if not re.match(r'^.*[()\[\]]+.*$', w):
        return w

    dbg("\t[%s]" % (w, ))

    if '(' not in w:
        w = w.strip(')')
    elif ')' not in w:
        w = w.strip('(')

    # remove ballanced brackets:
    while '[' in w and ']' in w:
        w = w.replace('[', '', 1).replace(']', '', 1)

    w = re.sub(r'^(^.*)\((.+)\)(.*)$', r'\1\2\3', w)

    dbg("-->\t[%s]" % (w, ))

    return w

# Sanity-check a Fixes: tag
#
# @s: the Fixes: tag string to check
def tag_sanity_check_fixes(s):
    print(("Checking tag [%s]" % (s, )))

    (sha1, name) = s.split(" ", 1)

    # check sha1 is all hex
    try:
        int(sha1, 16)
    except ValueError as e:
        sys.stderr.write("tag_sanity_check_fixes: SHA1 %s\n" % (e, ))
        sys.exit(1)

    # check sha1 is in the repo
    repo = Repo(".")
    git = repo.git
    try:
        git.tag('--contains', sha1)
    except Exception as e:
        sys.stderr.write("tag_sanity_check_fixes: SHA1 not in repo: %s\n" % (e, ))
        sys.exit(1)

    # compare the commit names too
    name = name.strip('("")')
    commit_name = git.show('--no-patch', '--pretty=format:%s', sha1)
    if name != commit_name:
        sys.stderr.write("tag_sanity_check_fixes: commit name mismatch: [%s] vs [%s]\n" % \
                         (name, commit_name, ))
        sys.exit(1)

    return s

#
### spellchecker stuff
dc = None

# my words
dc_words = [ "ABI", "ACPI", "AMD", "AMD64",
         # that's some stupid dictionary
         "amongst",
          "API", "APM", "APU", "arm64", "asm",
         "binutils", "bitmask", "bitfield", "cmdline", "config", "CPPC", "CPUID",
         "DMA", "DIMM", "e.g.", "e820", "EAX", "EDAC", "EFI", "EHCI", "ENQCMD", "EPT", "fixup",
         "GHCB", "GHCI", "GPR", "GUID", "HLT", "hugepage",
         "hypercall", "HV", "I/O", "initializer", "initrd", "IRQ", "IST", "JMP", "kallsyms",
         "KASAN", "kdump", "kprobe", "livepatch", "lvalue",
         "MCA", "MCE", "memmove",
         "memtype", "MMIO", "modpost", "MOVDIR64B", "MSR", "MTRR", "NMI", "noinstr",
         "NX", "offlining", "paravirt", "PASID", "PCI", "pdf", "percpu", "preemptible",
         "PTE",
         "PV", "PVALIDATE", "RDMSR", "rFLAGS", "RMP", "RMPADJUST", "Ryzen", "SEV", "SEV-ES",
         "SEV-SNP", "SIGSEGV", "Skylake", "SME", "SNP", "STI", "strtab", "struct", "swiotlb",
         "symtab", "syscall",
         "TDCALL", "TDGETVEINFO",
         "TDVMCALL", "TDX", "TLB",
         "UMC", "UML",
         # too late for that one to enforce even as the dictionary says it is wrong
         "untrusted",
         "userspace", "vCPU",
         "VM", "VMM", "VMCALL", "VMCB", "VMEXIT",
         "VMGEXIT", "VMLAUNCH", "VMSA", "vTOM", "WBINVD", "WRMSR", "x86", "Xen", "Xeon", "XSAVE" ]

dc_non_words = [ "E820", "X86" ]

# prominent kernel vars which get mentioned often in commit messages and comments
known_vars = [ '__BOOT_DS', 'fpstate', 'kptr_restrict', 'pt_regs', 'sme_me_mask',
               'sysctl_perf_event_paranoid', 'xfeatures' ]

def load_spellchecker():
    global dc

    dc = enchant.Dict("en_US")

    for w in dc_words:
        dc.add(w)

    for w in dc_non_words:
        dc.remove(w)

def spellcheck_func_name(w, prev_word):
    """
    Check a function's name

    """
    if w.endswith('()'):
        dbg("Skip function name: [%s]" % (w, ))
        return True
    else:
        if '_' in w and prev_word != "struct":
            # all caps - likely a macro name
            if re.match(r'^[A-Z0-9_]+$', w):
                dbg("Skip macro name: [%s]" % (w, ))
                return True

            return False

        return True

# known words as regexes to avoid duplication in the list above
regexes = [ r'BIOS(e[sn])?', r'boot(loader|params?|up)', r'MOVSB?', r'params?', r'PS[CP]',
            r'sev_(features|status)', r'virtualized?' ]

def spellcheck_regexes(w):
    """
        Check word @w against a list of regexes of known words
    """

    for rgx in regexes:
        if re.match(rgx, w):
            dbg("Skip regexed word: [%s]" % (w, ))
            return True

    return False


def spellcheck_hunk(pfile, hunk):
    """
        Spellcheck added lines if they're comments or Documentation
        @pfile: unidiff.patch.PatchedFile object
        @hunk:  unidiff.patch.Hunk object

    """

    # spellcheck .rst files fully
    if pfile.target_file.endswith(".rst"):
        for l in hunk.target_lines():

            # only newly added lines
            if not l.is_added:
                continue

            line = str(l)

            spellcheck(line, "Documentation", None)

        return

    # spellecheck flags
    flags = { 'check_func': True }

    for l in hunk.target_lines():
        line = str(l)
        # kernel-doc comment?
        m = re.match(r'\+\s*/\*\*\s*', line)
        if m:
            flags['check_func'] = False

        m = re.match(r'^\+\s+\*\s+.*$', line, re.I)
        if m:
            spellcheck(line, "comment", flags)

        # end of comment?
        m = re.match(r'^\+\s+\*\/', line)
        if m:
            flags['check_func'] = False

def spellcheck(s, where, flags):
    """
        Spellcheck a string @s, found @where: {comment, commit message, etc}

        @flags: a dictionary of bitfields which carry binary information which
                control spellchecking aspects

    """
    global dc

    for line in s.splitlines():
        # see if the line contains a commit reference and check it if so
        if re.match(r'^.*(?P<sha1>[a-f0-9]{7,})\s?\(\".*\"\).*', line):
            tag_sanity_check_fixes(line.strip())
            continue

        # special data in the commit message
        if where == "commit message" and line.startswith("  "):
            continue

        # URLs - ignore them
        line = re.sub(r'https?://[a-z0-9:/.-]+', '', line)

        # filenames and -paths, ditto
        line = re.sub(r'\s?/?(\w+/)*\w+\.[chS]', '', line)

        # remove fullstops ending a sentence - not other dots, as in "i.e." for example.
        line = re.sub(r'\.(\s?([A-Z]|$))', r' \1', line)

        # replace "word/word" with "word word" so that the line can be
        # split into words properly
        line = re.sub(r'(\w+)\/(\w+)', r'\1 \2', line)

        # '/' to split "word/word" formulations
        words = re.split(r'[\s/]', line)

        for i, w in enumerate(words):
            # remove punctuation
            w = w.strip('`\',*+:;!|<>"=')

            # remove prepended chars
            w = w.lstrip('%')

            w = strip_brackets(w)

            if not w:
                continue

            # only non-alphabetical chars left?
            if re.match(r'^[-]*$', w):
                dbg("Only non-alpha chars left: [%s]" % (w, ))
                continue

            dbg("%s: [%s]" % (where, w, ))

            # bold font, for example: "_especially_"
            if w.startswith('_') and w.endswith('_'):
                w = w.lstrip('_')
                w = w.rstrip('_')

            # local asm label
            if w.startswith('.L'):
                continue

            # skip SHAs
            if re.match(r'^[a-f0-9]{12,40}$', w, re.I):
                dbg("Skip SHA: [%s]" % (w, ))
                continue

            if w.startswith("CONFIG_"):
                dbg("Skip CONFIG_ item: [%s]" % (w, ))
                continue

            if w in known_vars:
                dbg("Skip known_vars [%s]" % (w, ))
                continue

            if spellcheck_regexes(w):
                continue

            # Check function names
            if flags and flags['check_func']:
                ret = spellcheck_func_name(w, words[i - 1])
                if not ret:
                    warn(1, ("Function name doesn't end with (): [%s]" % (w, )))
                    print(" [%s]" % (line, ))
                    continue
                else:
                    continue

            # kernel-doc arguments
            if re.match(r'^@\w+:?$', w):
                dbg("Skip kernel-doc argument: [%s]" % (w, ))
                continue

            # number: decimal...
            if re.match(r'^[0-9]+$', w):
                dbg("Skip decimal number: [%s]" % (w, ))
                continue

            # number: hex, units, ...
            if re.match(r'^(0x[0-9a-f]+|[0-9a-f]+(K|Mb))$', w, re.I):
                dbg("Skip number [%s]" % (w, ))
                continue

            # x86 trap names
            if re.match(r'^\#[A-ZA-Z]', w):
                dbg("Skip x86 trap name: [%s]" % (w, ))
                continue

            # x86 registers
            # if re.match(r'r([abcd][ipx]|[89]|1[0-5])', w, re.I):
            if re.match(r'([re]?[abcd]x|r([89]|1[0-5]))', w, re.I):
                dbg("Skip x86 register: [%s]" % (w, ))
                continue

            # x86-specific abbreviations
            if re.match(r'(VMPL[0-3]?|DDR[1-5]?)', w):
                dbg("Skip hw-specific abbrev.: [%s]" % (w, ))
                continue

            # kernel cmdline params
            if re.match(r'^\w+=([\w,]+)?$', w):
                dbg("Skip cmdline param: [%s]" % (w, ))
                continue

            # versions...
            if re.match(r'v\d+$', w, re.I):
                dbg("Skip version: [%s]" % (w, ))
                continue

            # C keywords
            if re.match(r'#ifdef', w):
                dbg("Skip C keyword: [%s]" % (w, ))
                continue

            # sections
            if re.match(r'(\.bss|\.data|\.head\.text)', w):
                dbg("Skip section name: [%s]" % (w, ))
                continue

            # error value defines
            if re.match(r'-E(EINVAL|EXIST|OPNOTSUPP)', w):
                dbg("Skip error define: [%s]" % (w, ))
                continue

            # tool options
            if re.match(r'-[\w\d=-]+$', w, re.I):
                dbg("Skip tool option: [%s]" % (w, ))
                continue

            # BLA-<adjective>
            m = re.match(r'([\w-]+)-(active|controlled|related|specific|validated)', w)
            if m:
                if dc.check(m.group(1)):
                    dbg("Skip BLA-<adjective>: [%s]" % (w, ))
                    continue

            # <word>-BLA
            m = re.match(r'non-(\w+)', w)
            if m:
                if dc.check(m.group(1)):
                    dbg("Skip <word>-BLA: [%s]" % (w, ))
                    continue

            # reference to register fields like GHCBData[55:52], for example
            if re.match(r'\w+\[\d+(:\d+)?\]', w, re.I):
                dbg("Skip reference to register fields: [%s]" % (w, ))
                continue

            # misc numbering with misc formatting
            if re.match(r'^#\d+$', w):
                dbg("Skip misc numbering: [%s]" % (w, ))
                continue

            # skip words containing '_' - they're likely variable or function names
            if '_' in w:
                dbg("Skip '_'-containing word: [%s]" % (w, ))
                continue

            if not dc.check(w):
                # see if it is plural or genitive: "<word>'s"
                if dc.check(w.rstrip('\'s')):
                    continue

                # gerund?
                if dc.check(w.removesuffix('ing')):
                    dbg("Skip gerund: [%s]" % (w, ))
                    continue

                print(line)
                print(("Unknown word [%s] in %s." % (w, where, )))
                suggestions = dc.suggest(w)
                if suggestions:
                    print("Suggestions: %s" % (suggestions, ))
                print()

#
### Class Patch

class Patch:
    """
    A class representing the current patch being worked on
    """

    def __init__(self, msg):
        """ Constructor

        @msg: the parsed email.message instance
        """

        # Patch attributes
        # patch version
        self.version = 0
        # ... number
        self.number = 0
        self.date = None

        # message-id used for the Link: tag
        self.message_id = None

        # The commit message as string
        self.commit_msg = None

        # diffstat of current patch.
        self.diffstat = None

        # the actual diff
        self.diff = None

        # init ordered dictionary for tags processing
        self.od = collections.OrderedDict()
        # build in the proper order
        self.od['Fixes'] = []
        self.od['Reported-by'] = []
        self.od['Suggested-by'] = []
        self.od['Signed-off-by'] = []
        # Co-developed-by: should be behind the SOB because format_tags() is picking the proper
        # one out so no need for that order here
        self.od['Co-developed-by'] = []
        self.od['Reviewed-by'] = []
        self.od['Acked-by'] = []
        self.od['Tested-by'] = []
        self.od['Cc'] = []
        self.od['Link'] = []
        self.od['other'] = []

        self.orig_subject = msg['subject']
        info("Patch: orig_subject: [%s]" % (self.orig_subject, ))

        self.sender  = msg['from']
        self.author = self.sender
        info("Patch: sender: [%s]" % (self.sender, ))

        if msg['date']:
            self.date = msg['date']

        if msg['message-id']:
            self.message_id = msg['message-id'].strip('<>')

        # The whole patch as string
        self.patch = msg.get_payload()

        self.process_patch()

    def __repr__(self):
        return (
"""Class patch:
    original subject: [%s]
             subject: [%s]
              sender: [%s]
              author: [%s]
             version: [%d]
              number: [%d]
                name: [%s]
                date: [%s]
          message-id: [%s]
""" % (self.orig_subject, self.subject, self.sender, self.author,
       self.version, self.number, self.name, self.date, self.message_id))

    def massage_subject(self):
        """
        Massage original subject into submission
        """

        s = self.orig_subject

        # strip [PATCH... ]
        s = re.sub(r'\[PATCH[^]]*\]\s?', '', s)

        # remove funky newlines
        s = re.sub(r'\n', '', s)

        try:
            (prefix, title) = s.rsplit(':', 1)
        except ValueError:
            sys.stderr.write(("Cannot split subject; no prefix?: [%s]\n" % (s, )))
            sys.exit(1)

        # replace commas in the subject with slashes. I need to avoid replacing when it looks like
        # "x86/MCE/AMD, EDAC/amd64:"
        prefix = re.sub(r'([:alnum:]+),([:alnum:]+)', '\1/\2', prefix)

        # uppercase "EDAC":
        prefix = re.sub(r'edac/', 'EDAC/', prefix)

        assert prefix != s, "Subject does not contain ':'"

        # capitalize first letter
        title = title.lstrip()
        new_title = title[0].upper() + title[1:]

        spellcheck(new_title, "Subject", None)

        new_subj = prefix + ": " + new_title

        if s != new_subj:
            print("Massaged subject:")
            print(" [%s]\n [%s]" % (s, new_subj, ))

        # set new subject
        self.subject = new_subj

    def massage_author(self):
        """ massage patch author

        Apply transformations to the patch author

        """
        a = self.author

        dbg("")

        m = re.match(r'(?P<author_name>^.*)(?P<author_email>\<.*)', a, re.IGNORECASE)
        if m:
            author_name = m.group('author_name')

        # strip quotes
        author_name = re.sub(r'"', '', author_name)

        if "," in author_name:
            last, first = author_name.split(',')
            last  = last.strip()
            first = first.strip()

            a = ("%s %s %s" % (first, last, m.group('author_email'), ))

        if self.author != a:
            print("%s: New author: [%s]" % (__func__(), a, ))
            self.author = a

    def determine_versioning(self):
        version = 1
        rest = ''

        # split the string and deal with each piece later: easier.
        m = re.match(r'^.*\[.*patch(?P<version>.*?)?(?P<rest>\d+\/\d+)?\]', self.orig_subject, re.I)
        if m:
            tmp_ver = m.group('version')
            if tmp_ver:
                # remove non-numeric chars
                v = re.sub(r'[^0-9]', '', tmp_ver)
                if v:
                    version = int(v)

            if m.group('rest'):
                rest = m.group('rest')

        dbg("version: [%s]" % (version, ))
        dbg("Patch: rest: [%s]" % (rest, ))

        # patch numbering
        pnum = 1
        max_pnum = 1
        m = re.match(r'\s*(?P<pnum>\d+)\/(?P<max_pnum>\d+)', rest)
        if m and m.group('pnum'):
            pnum = int(m.group('pnum'))

        if m and m.group('max_pnum'):
            max_pnum = int(m.group('max_pnum'))

        dbg("Patch: ver: %d, range: %d-%d" % (version, pnum, max_pnum))

        # patch name
        m = re.match(r'^.*\[.*patch[^]]*\]\s*(?P<pname>.*)', self.orig_subject, re.I)
        if m and m.group('pname'):
            dbg(("Patch: pname: [%s]" % (m.group('pname'), )))
            pname = m.group('pname')
        else:
            print("Error: cannot match patch name. Falling back to subject... ")
            pname = self.subject

        # remove funny chars
        pname = re.sub(r'[\',()\[\]!&<>$"|\*;`]', '', pname)
        pname = re.sub(r'[:/]\s?', '-', pname)
        pname = pname.lower()
        pname = re.sub(r'\s+', '_', pname)

        self.version = version
        self.number = pnum
        self.name = pname

    def postprocess_commit_msg(self, plines):
        """
            @plines: a list of commit message lines
        """

        for line in plines:
            # Scan for a potential new From:
            m = re.match(r'^\s?From:\s?(.*)', line, re.IGNORECASE)
            if m:
                new_from = m.group(1)
                if new_from != self.sender:
                    self.author = new_from
                    print("Found new author: [%s]" % (new_from))
                    plines.remove(line)

        self.commit_msg = "\n".join(plines[:])

    def verify_diff(self):
        ps = unidiff.PatchSet(self.diff)

        # a PatchSet contains a bunch of PatchedFile's
        for pfile in ps:
            # each PatchedFile contains a bunch of Hunk's
            for hunk in pfile:
                for line in str(hunk).splitlines():
                    # check for unicode chars, aka https://trojansource.codes/
                    m = re.search(r'([^\x00-\xff])', line)
                    if m:
                        warn(1, "Unicode char [%s] (0x%x) in line: %s"
                                % (m.group(1), ord(m.group(1)), line, ))

                spellcheck_hunk(pfile, hunk)

                # strip the first two "a/" or "b/"
                f = pfile.target_file[2:]

                verify_binutils_version(f, hunk)
                verify_comment_style(f, hunk)

    def add_tag(self, line):
        m = re.search(r'^(.*):\s*(.*)$', line)
        if m.group(1) and m.group(2):
            info("Adding tag [%s]" % (line, ))
            self.od[m.group(1)] += m.group(2)
        else:
            warn(1, "add_tag: Cannot match tag properly\n")

    def process_tags(self, clines):
        """
        Process tags from the commit message, backwards

        Return how many lines it ate
        """
        global sob

        ret_lines = 0

        dbg("")

        for line in reversed(clines):
            # relies on the fact that tags and commit message are separated by an empty line
            if not line:
                break

            dbg(line)

            (a, b) = line.split(':', maxsplit=1)
            tag = a.strip()
            name_email = b.strip()

            dbg("--> tag: [%s] name: [%s]" % (tag, name_email, ))
            ret_lines += 1

            # Skip all Cc: tags except stable and explicitly added ones
            if tag.lower() == "cc":
                m = re.match(r'^\s*<stable@vger.kernel.org>\s*.*$', name_email, re.I)
                if not m:
                    warn(1, ("Skipping Cc: %s" % (name_email, )))
                    continue

            # check Fixes: tag
            if tag.lower() == 'fixes':
                tag_sanity_check_fixes(name_email)

            info("Adding tag %s: %s" % (tag, name_email, ))
            # prepend tag because we're scanning the tag list backwards
            self.od[tag].insert(0, name_email)

        # add global sob
        if sob:
            self.od['Signed-off-by'].append(sob)

        dbg(self.od)
        dbg("done")

        return ret_lines

    def __parse_diffstat(self, lines):
        """
        Parse and assign the diffstat from lines[]

        Return how many lines the diffstat is
        """
        ret = 0
        dfst = []

        for line in lines:
            # git or quilt-type patch
            if line.startswith("diff"):
                break

            # pick out only the actual diffstat lines
            # "<filepath> | <num> +-"
            if re.match(r'^.*\|\s+\d+\s+[+-]+\s?$', line):
                dfst.append(line)

            # X file(s) changed, Y insertions?(+), Z deletions?(-)
            if re.match(r'^.*files?\s+changed(.*insertions?\(\+\))?(.*deletions?\(\-\))?$', line):
                dfst.append(line)

            # create/delete mode
            if re.match(r'^\s+(create|delete) mode [0-9]+ .*', line):
                dfst.append(line)

            ret += 1

        self.diffstat = "\n".join(dfst[:])

        dbg("\n" + self.diffstat)
        dbg("EOF diffstat")

        return ret


    def parse_patch(self):
        """
        Go through the patch and pick apart stuff like tags, diffstat, hunks etc.
        """
        i = 0

        plines = self.patch.splitlines()

        for line in plines:
            dbg(" -> [%s]" % (line, ))

            # take only the first "---" split line. Subsequent ones can contain
            # changelog history which git ignores
            if line == "---" and not self.commit_msg:
                tag_lines = self.process_tags(plines[0:i])

                dbg("--> Commit message")
                self.postprocess_commit_msg(plines[0:i - tag_lines])
                dbg(self.commit_msg)
                dbg("End of Commit message")

                # got commit message and tags, remove it from plines and start afresh
                # i+1 in order to skip "---" too
                plines = plines[i+1:]
                break

            i += 1


        dfst_len = self.__parse_diffstat(plines)

        # remove diffstat
        plines = plines[dfst_len:]

        # skip potential sender notes etc
        i = 0
        for line in plines:
            if line.startswith("diff") or line.startswith("---"):
                break
            i += 1

        # plines contains the actual diff now, save it.
        self.diff = "\n".join(plines[i:])

    def verify_subject(self):
        """
        Check the subject prefix matches the subsystem being touched.
        """

        if not self.diff:
            return

        ps = unidiff.PatchSet(self.diff)

        for pfile in ps:
            if pfile.path.startswith("arch/x86/"):
                # reverts start with 'Revert "'
                if self.subject.startswith("Revert \""):
                    return

                # do not check if patch touches multiple subsystems
                if "/kvm/" in pfile.path or "/svm" in pfile.path:
                    return
            # ditto
            else:
                return

        # WIP: make sure there's no second ':' in the subject
        # needs improving
        if not re.match(r'^x86(/[\w/-]+)?:[^:]*$', self.subject):
            err(("Subject prefix wrong: [%s]" % (self.subject, )))

    def verify_commit_message(self):
        """
        Do all kinds of checks to the commit message
        """

        lines = self.commit_msg.splitlines()

        for i, l in enumerate(lines):
            warn(re.match(r'\W?we\W', l, re.I),
                          ("Commit message has 'we':\n [%s]" % (l, )))

            warn(re.match(r'(.*this\s+patch.*)', l, re.I),
                          ("Commit message has 'this patch':\n [%s]" % (l, )))

            if re.search(r'[a-f0-9]{7,40}\s?\(\".*', l, re.I):
                verify_commit_quotation(lines[i - 1], lines[i], lines[i + 1])

        spellcheck(self.commit_msg, "commit message", None)

    def format_tags(self, f):
        """
        @f: Write into this file stream
        """

        od = self.od
        cdb = "Co-developed-by"

        for tag in od:
            if not od[tag]:
                continue

            for v in od[tag]:
                # Slap Co-developed-by before the SOB
                if tag == 'Signed-off-by':
                    if v in od[cdb]:
                        info("%s: %s" % (cdb, v, ))
                        f.write(("%s: %s\n" % (cdb, v, )))
                        od[cdb].remove(v)

                info("%s: %s" % (tag, v, ))
                f.write(("%s: %s\n" % (tag, v, )))

        # slap the Link at the end
        info("Link: https://lore.kernel.org/r/%s\n" % (self.message_id, ))
        f.write(("Link: https://lore.kernel.org/r/%s\n" % (self.message_id, )))

    def process_patch(self):
        """
        Call all the patch massaging methods here. Called by the constructor as the last thing after
        having set everything up before.
        """

        self.parse_patch()
        # parse_patch->postprocess_commit_msg() can potentially parse a new author from From:
        # So call massage_author() after it
        self.massage_subject()
        self.determine_versioning()
        self.massage_author()
        self.verify_subject()
        self.verify_commit_message()
        self.verify_diff()

    def format_patch(self):
        """
        Write patch to tmp_dir after having processed it properly
        """

        global tmp_dir

        if not tmp_dir:
            warn(1, "Output tmp_dir not set")
            return

        final = ("%s/%02d-%s-new.patch" % (tmp_dir, self.number, self.name, ))

        print("Patch: will write [%s]" % (final, ))

        f_out = open(final, "w")

        info(" | From: %s" % (self.author, ))
        f_out.write(("From: %s\n" % (self.author, )))

        info(" | Date: %s" % (self.date, ))
        f_out.write(("Date: %s\n" % (self.date, )))

        info(" | Subject: %s" % (self.subject, ))
        f_out.write(("Subject: %s\n\n" % (self.subject, )))

        info(" |")
        info(" | PATCH CONTENTS:")

        info(" | commit_msg:")
        info(self.commit_msg)
        f_out.write(("%s\n" % (self.commit_msg, )))

        info(" | tags:")
        self.format_tags(f_out)

        f_out.write("---\n")

        info(" | diffstat:")
        info(self.diffstat)
        f_out.write(("%s" % (self.diffstat, )))

        f_out.write("\n\n")

        info(" | diff")
        info(self.diff)
        f_out.write(("%s\n" % (self.diff, )))

        info(" | END OF PATCH CONTENTS:")

        # flush patch out here

        f_out.close()

### End of class Patch

#
### diff verification using unidiff.patch.Hunk class instances as an arg

###
# check whether there's a binutils version supplied in a comment over naked opcode bytes with
# inline asm directive .byte
#
def verify_binutils_version(f, h):
    inline_asm = False
    opcodes = False
    lines = []
    asm_line = None

    for l in h.target_lines():
        line = str(l)

        # first, scan for the asm volatile() statement
        m = re.match(r'^\s?\+\s?asm(\svolatile)?\s?\(', line)
        if m:
            inline_asm = True
            asm_line = l

        # now, scan for the .byte directive
        if inline_asm:
            m = re.match(r'^\s?\+.*\.byte(\s[x0-9a-f,])+', line, re.I)
            if m:
                opcodes = True
                break

        # buffer containing past lines, the comment must be in there, if at all
        lines.append(line)

    if not opcodes: return

    for l in lines:
        m = re.match(r'^.*binutils\s[\d.]+.*', l)
        if m:
            return

    for l in lines:
        print(l, end="")
    err("No binutils version specified over naked opcode bytes at %s:%d" % (f, asm_line.target_line_no, ))

# check comment formatting
def verify_comment_style(pfile, h):
    in_comment = False
    comment_start = None

    for line in h.target_lines():
        l = str(line)

        # does the comment start have chars after the '*'?
        if not in_comment:
            m = re.match(r'^.*/\*\s+\w+', l, re.I)
            if m:
                in_comment = True
                comment_start = l
                continue

        if in_comment:
            warn(re.match(r'^\+?\s*\*\s*\w*', l),
                 "Multi-line comment needs to start text on the second line:\n [%s]\n" %
                 (comment_start.strip(), ))
            in_comment = False

    # check side comments only in .c/.h files
    if not pfile.endswith(('.c', '.h')): return

    # exceptions to the rule
    if pfile == "arch/x86/include/asm/cpufeatures.h": return

    for line in h.target_lines():
        # look at only added (+) lines
        if not line.is_added:
            continue

        l = str(line)

        warn(re.match(r'^.*[;)]\s*/\*.*$', l), "No tail comments please:\n %s:%d [%s]\n" %
             (pfile, line.target_line_no, l.strip(), ))


def verify_commit_quotation(prev, cur, nxt):
    """
    Verify if a commit is quoted properly. Args are the three lines surrounding the sha1
    """

    if not prev and not nxt and cur.startswith("  "):
        return

    warn(1, "line [%s]" % (cur, ))
    warn(1, "The proper commit quotation format is:\n<newline>\n[  ]<sha1, 12 chars> (\"commit name\")\n<newline>")
###


def check_unicode_chars_in_patch(msg):

    lines = msg.as_string().splitlines(True)

    # skip commit message
    for line in lines:
        # people create patches without that "---" line. Use two match objects because
        # python can't do goto labels which will fit perfectly here
        m0 = re.match(r'^---$', line)
        m1 = re.match(r'^diff (--git)? a/.* b/.*', line)
        if m0 or m1:
            break

    for i, line in enumerate(lines):
        if re.search(r'[^\x00-\xff]', line):
            print("Line %d has a unicode char: %s" % (i, line, ))
            return True

    return False

def smoke_check(msg, force):

    dbg("")

    if check_unicode_chars_in_patch(msg):
        if not force:
            sys.exit(1)

## main
#
def main(args):
    global verbose, dc_words

    # set verbosity level
    if args.verbose:
        # re_flags |= re.DEBUG
        verbose = args.verbose

    input_file  = args.infile[0]
    if not os.path.isfile(input_file):
        sys.stderr.write("Cannot access %s, exiting...\n" % (input_file, ))
        sys.exit(1)

    with open(input_file, 'rb') as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    smoke_check(msg, args.force)

    if args.add_to_whitelist:
        for w in args.add_to_whitelist.split():
            dc_words.append(w)

    # needs to run after --add-to-whitelist
    load_spellchecker()

    fp = open(input_file, 'r')
    p = Patch(msg)
    fp.close()

    # add any tags supplied on the cmdline
    if args.add_tag:
        for tag in args.add_tag:
            p.add_tag(tag)

    print(p)

    p.format_patch()

def parse_config_file():
    global tmp_dir, sob

    cfg = configparser.ConfigParser()
    cfg.read(os.path.expanduser('~/.verify.cfg'))

    try:
        tmp_dir = cfg['main']['temp']
    except:
        err("No temp directory configured")

    try:
        sob = cfg['main']['sob']
    except:
        warn(1, "No author SOB email configured")

def init_parser():
    """ read cmdline args

        returns:
            options:dict -- config options
    """

    parser = argparse.ArgumentParser(description='patch preparation script', prog='prep-patch')

    parser.add_argument("--add-tag",
                        help="Add tag to the tags list in the patch",
                        action="append")

    parser.add_argument("--add-to-whitelist",
                        type=str,
                        help="Add list of words to the words whitelist")

    parser.add_argument("-f", "--force",
                        action="store_true",
                        default=False,
                        help="Force patch writeout")

    parser.add_argument('infile', nargs=1)

    parser.add_argument("-v", "--verbose",
                        action="count",
                        help="Enable more verbose output")

    return parser.parse_args()

if __name__ == '__main__':
    global args

    parse_config_file()

    args = init_parser()

    # check if we're in a git repo
    if not os.path.exists(os.getcwd() + "/.git"):
        os.chdir(os.path.expanduser("~") + "/kernel/linux/")
        info("Switching CWD to kernel repo.")

    main(args)
