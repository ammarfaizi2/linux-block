#!/usr/bin/python3

"""
vp.py - Patch verifier and massager tool
"""


# TODO (and potential ideas):
#
# - add a check against hunks with file paths arch/x86/boot/(compressed/)? which #include <linux/*>
# headers and warn if so.
# 
# - a8: switch to logging module maybe:
#   https://docs.python.org/3/howto/logging.html#logging-basic-tutorial

import re
import sys
import time
import os.path
import inspect
import argparse
import datetime
import traceback
import requests             # for url checking
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

def warn_on(cond, s):
    if cond:
        print(("%s: Warning: %s" % (__func__(), s, )))

def warn(s):
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

# remove brackets which are left overs from splitting a line into words,
# but leave ballanced ones which denote an array or a function name
# inspired by 
# https://stackoverflow.com/questions/56450268/how-to-check-unbalanced-brackets-in-python-3
def strip_brackets(w):
    if not rex_brackets.match(w):
        return w

    dbg("\t|%s|" % (w, ))

    # skip register field specifications
    if rex_reg_field.match(w):
        dbg("regf: |%s|" % (w, ))
        return w

    pairs = {"{": "}", "(": ")", "[": "]"}
    stack = []

    # XXX: this needs more thought. It would fudge a case with arguments:
    # function_name(arg1, arg2, arg3, ...)
    # I need to think about what to do here.
    for c in w:
        if c in "{([":
            stack.append(c)
        elif stack and c == pairs[stack[-1]]:
            stack.pop()
        # unballanced closing bracket, zap it
        elif c in "])}":
            w = w.replace(c, '', 1)
        # unballanced opening bracket, zap it
        elif stack:
            w = w.replace(stack.pop(), '', 1)

    dbg("-->\t|%s|" % (w, ))

    return w

# Sanity-check a commit reference
#
# @s: the commit reference string to check
def verify_commit_ref(sha1, name):
    print(("Checking commit ref [%s %s]" % (sha1, name, )))

    repo = Repo(".")
    git = repo.git

    # check sha1 is all hex
    try:
        int(sha1, 16)
    except ValueError as e:
        sys.stderr.write("verify_commit_ref: SHA1 %s\n" % (e, ))
        sys.exit(1)

    # min 12 of length
    if len(sha1) < 12:
        sys.stderr.write("Commit sha1 (%s) needs to be at least 12 chars long:\n" % (sha1, ))
        try:
            print(git.show('-s', '--pretty=format:%h (\"%s\")', sha1))
        except Exception as e:
            sys.stderr.write("verify_commit_ref: SHA1 len exception %s\n" % (e, ))

    # check sha1 is in the repo
    try:
        git.tag('--contains', sha1)
    except Exception as e:
        sys.stderr.write("verify_commit_ref: SHA1 not in repo: %s\n" % (e, ))
        sys.exit(1)

    # compare the commit names too
    name = name.removeprefix('("').removesuffix('")')
    commit_name = git.show('--no-patch', '--pretty=format:%s', sha1)
    if name != commit_name:
        sys.stderr.write("verify_commit_ref: commit name mismatch: [%s] vs [%s]\n" % \
                         (name, commit_name, ))
        sys.exit(1)

#
### spellchecker stuff
dc = None

# my words
dc_words = [ "ABI", "ACPI", "AMD", "AMD64",
         # that's some stupid dictionary
         "amongst",
         "AMX", "API", "APM", "APU", "arm64", "asm",
         "binutils", "bitmask", "bitfield", "CMCI", "cmdline", "config", "CPPC", "CPUID",
         "DMA", "DIMM", "e820", "EAX", "EDAC", "EFI", "EHCI", "ENQCMD", "EPT", "fixup",
         "FRU", "GPR", "GUID", "HLT", "hotplug", "hugepage", "Hygon",
         "hypercall", "HV", "I/O", "IBT", "initializer", "initrd", "IRET", "IRQ", "JMP", "kallsyms",
         "KASAN", "kdump", "kexec", "KVM", "LFENCE", "livepatch", "lvalue",
         "MCA", "MCE", "memmove",
         "memtype", "MMIO", "modpost", "MOVDIR64B", "MSR", "MTRR", "NMI", "noinstr",
         "NX", "OEM", "offlining", "ok", "PASID", "PCI", "pdf", "percpu", "perf", "preemptible",
         "prepend", # derived from append, not in the dictionaries
         "PTE", "PPIN",
         "PV", "PVALIDATE", "RDMSR", "retpoline", "rFLAGS", "RMP", "RMPADJUST", "Ryzen",
         "SIGSEGV", "Skylake", "SME", "SNP", "Spectre", "STI", "strtab", "struct", "swiotlb",
         "symtab", "syscall", "sysfs", 
         "TDCALL", "TDGETVEINFO",
         "TDVMCALL", "TLB", "TODO",
         "UMC", "UML",
         # too late for that one to enforce even as the dictionary says it is wrong
         "untrusted",
         "userspace", "vCPU",
         "VM", "VMM", "VMCALL", "VMCB", "VMEXIT",
         "VMGEXIT", "VMLAUNCH", "VMSA", "vTOM", "WBINVD", "WRMSR", "XCR0", "Xen", "Xeon", "XSS" ]

dc_non_words = [ "E820", "X86" ]

# prominent kernel vars, etc which get mentioned often in commit messages and comments
known_vars = [ '__BOOT_DS', 'boot_params', 'cpuinfo_x86', 'earlyprintk', 'fpstate', 'kobj_type',
           'kptr_restrict', 'pt_regs',
           'ptr', 'set_lvt_off', 'setup_data',
           'sme_me_mask', 'sysctl_perf_event_paranoid', 'threshold_banks', 'xfeatures' ]

# known words as regexes to avoid duplication in the list above
regexes_pats = [ r'^AVX(512)?(-FP16)?$', r'BIOS(e[sn])?', r'boot(loader|params?|up)',
             r'default_(attrs|groups)', r'^DDR([1-5])?$', r'^[Ee].g.$', r'^[eE]?IBRS$', r'^E?VEX$',
            r'^GHC(B|I)$', r'^Icelake(-D)?$', r'I[DS]T', r'^[ku]probes?$', r'MOVSB?', r'^param(s)?$',
            r'^([Pp]ara)?virt(ualiz(ed|ing|ation))?$', r'PS[CP]',
            r'sev_(features|status)', r'^SEV(-(ES|SNP))?$', r'T[DS]X', r'^VMPL([0-3])?$', r'^x86(-(32|64))?$',
            r'^XSAVE[CS]?$' ]

def load_spellchecker():
    global dc, regexes, regexes_pats, rex_asm_dir, rex_brackets, \
rex_c_keywords, rex_c_macro, rex_comment, rex_comment_end, \
rex_commit_ref, rex_decimal, rex_errval, rex_fnames, rex_gpr, rex_hyphenated, \
rex_kcmdline, rex_kdoc_arg, rex_kdoc_cmt, rex_misc_num, rex_non_alpha, \
rex_opts, rex_paths, rex_reg_field, rex_sections, rex_sent_end, rex_sha1, \
rex_struct_mem, rex_units, rex_url, rex_version, rex_word_bla, \
rex_word_split, rex_x86_traps


    dc = enchant.Dict("en_US")

    for w in dc_words:
        dc.add(w)

    for w in dc_non_words:
        dc.remove(w)

    # compile all regexes
    # Use /usr/share/doc/pythonX.X/examples/demo/redemo.py for checking
    rex_asm_dir     = re.compile(r'^\.(align|org)$')
    rex_brackets    = re.compile(r'^.*[()\[\]]+.*$')
    rex_c_keywords  = re.compile(r'#(ifdef|include)')
    rex_c_macro     = re.compile(r'^[A-Z0-9_]+$')
    rex_comment     = re.compile(r'^\+\s+\*\s+.*$', re.I)
    rex_comment_end = re.compile(r'^\+\s+\*\/')

    # a commit ref is either preceded by some uninteresting chars and a space or it begins on a
    # newline
    rex_commit_ref  = re.compile(r'^(.*\s)?(?P<sha1>[a-f0-9]{7,})\s(?P<commit_title>\(\".*\"\)).*')

    rex_decimal     = re.compile(r'^[0-9]+$')
    rex_errval      = re.compile(r'-E(EINVAL|EXIST|NODEV|NOMEM|OPNOTSUPP|PROBE_DEFER)')
    rex_fnames      = re.compile(r'\s?/?([\w-]+/)*[\w-]+\.[chS]')

    rex_gpr         = re.compile(r"""([re]?[abcd]x|     # the first 4
                                       r([89]|1[0-5])|  # the extended ones
                                       [re][ds]i|       # the other 2
                                       [re][bs]p)       # the last 2
                                        """, re.I | re.X)

    rex_hyphenated  = re.compile(r'([\w#-]+)-([\w#-]+)')
    rex_kcmdline    = re.compile(r'^\w+=([\w,]+)?$')
    rex_kdoc_arg    = re.compile(r'^@\w+:?$')
    rex_kdoc_cmt    = re.compile(r'\+\s*/\*\*\s*')
    rex_misc_num    = re.compile(r'^#\d+$')
    rex_non_alpha   = re.compile(r'^[-]*$')
    rex_opts        = re.compile(r'^-[\w\d=-]+$')    # assumption: tool options are lowercase
    # path spec can begin on a new line
    rex_paths       = re.compile(r'(^|\s)/[\w/_\*-]+\s')
    rex_reg_field   = re.compile(r'\w+\[\d+(:\d+)?\]', re.I)
    rex_sections    = re.compile(r'\.(bss|data|head(\.text)?|text)')

    rex_sent_end    = re.compile(r"""\.((\s+)?      # catch all spaces after the end of the sentence
                                                    # as some formatters add more than one for block
                                                    # formatting
                                  ([A-Z][a-z]+|$))  # Either another sentence starts here or EOL.
                                  """, re.VERBOSE)

    rex_struct_mem  = re.compile(r'\w+->\w+')
    rex_sha1        = re.compile(r'[a-f0-9]{12,40}', re.I)
    rex_units       = re.compile(r'^(0x[0-9a-f]+|[0-9a-f]+(K|Mb))$')
    rex_url         = re.compile(r'https?://[a-z0-9:/.-]+')
    rex_version     = re.compile(r'v\d+$', re.I)
    rex_word_bla    = re.compile(r'non-(\w+)')
    rex_word_split  = re.compile(r'(\w+)\/(\w+)')
    rex_x86_traps   = re.compile(r'^#[A-Z]{2,2}$')

    # precompile all regexes
    for pat in regexes_pats:
        regexes.append(re.compile(pat))

def spellcheck_func_name(w, prev_word):
    """
    Check a function's name

    """

    # remove crap from previous word
    prev = prev_word.strip('`\',*+:;!|<>"=')

    dbg("%s" % (w, ))

    if w.endswith('()'):
        dbg("Skip function name: [%s]" % (w, ))
        return True

    if w.endswith('[]'):
        dbg("Skip array name: [%s]" % (w, ))
        return True

    # linker range defines, heuristic only
    if w.startswith('__start_') or w.startswith('__end_'):
           return True

    # all caps - likely a macro name
    if rex_c_macro.match(w):
        dbg("Skip macro name: [%s]" % (w, ))
        return True

    if rex_struct_mem.match(w):
        dbg("Skip struct member: [%s]" % (w, ))
        return True

    return False


regexes = []

def spellcheck_regexes(w):
    """
        Check word @w against a list of regexes of known words
    """

    for rgx in regexes:
        m = rgx.match(w)
        if m:
            dbg("Skip regexed word: [%s] match: (%s)" % (w, m.group(0)))
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
        m = rex_kdoc_cmt.match(line)
        if m:
            flags['check_func'] = False

        m = rex_comment.match(line)
        if m:
            spellcheck(line, "comment", flags)

        # end of comment?
        m = rex_comment_end.match(line)
        if m:
            flags['check_func'] = True

def spellcheck(s, where, flags):
    """
        Spellcheck a string @s, found @where: {comment, commit message, etc}

        @flags: a dictionary of bitfields which carry binary information which
                control spellchecking aspects

    """
    global dc

    for line in s.splitlines():
        # see if the line contains a commit reference and check it if so
        m = rex_commit_ref.match(line)
        if m:
            verify_commit_ref(m.group('sha1'), m.group('commit_title'))
            continue

        # specially formatted text (cmdline output, etc) in the commit message, do not check
        if where == "commit message" and line.startswith("  "):
            continue

        # URLs - ignore them
        line = rex_url.sub('', line)

        # filenames, ditto
        line = rex_fnames.sub('', line)

        # paths... replace with a single \s because the regex is eating it
        line = rex_paths.sub(' ', line)

        # remove fullstops ending a sentence - not other dots, as in "i.e." for example.
        line = rex_sent_end.sub(r' \1', line)

        # replace "word/word" with "word word" so that the line can be
        # split into words properly
        line = rex_word_split.sub(r'\1 \2', line)

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
            if rex_non_alpha.match(w):
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
            if rex_sha1.match(w):
                dbg("Skip SHA: [%s]" % (w, ))
                continue

            if w.startswith("CONFIG_") or w.startswith("ARCH_"):
                dbg("Skip CONFIG_ item: [%s]" % (w, ))
                continue

            if w in known_vars:
                dbg("Skip known_vars [%s]" % (w, ))
                continue

            if spellcheck_regexes(w):
                continue

            # kernel cmdline params
            if rex_kcmdline.match(w):
                dbg("Skip cmdline param: [%s]" % (w, ))
                continue

            # error value defines
            if rex_errval.match(w):
                dbg("Skip error define: [%s]" % (w, ))
                continue

            # Check function names
            if flags and flags['check_func']:

                # it is only a heuristic anyway
                if '_' in w and words[i - 1] != "struct":
                    ret = spellcheck_func_name(w, words[i - 1])
                    if ret:
                        continue

                    warn_on(1, ("Function name doesn't end with (): [%s]" % (w, )))
                    print(" [%s]" % (line, ))

            # kernel-doc arguments
            if rex_kdoc_arg.match(w):
                dbg("Skip kernel-doc argument: [%s]" % (w, ))
                continue

            # number: decimal...
            if rex_decimal.match(w):
                dbg("Skip decimal number: [%s]" % (w, ))
                continue

            # number: hex, units, ...
            m = rex_units.match(w)
            if m:
                dbg("Skip hex number/unit [%s], match [%s]" % (w, m.group(0)))
                continue

            # x86 trap names
            if rex_x86_traps.match(w):
                dbg("Skip x86 trap name: [%s]" % (w, ))
                continue

            # x86 registers
            if rex_gpr.match(w):
                dbg("Skip x86 register: [%s]" % (w, ))
                continue

            # versions...
            if rex_version.match(w):
                dbg("Skip version: [%s]" % (w, ))
                continue

            # C keywords
            if rex_c_keywords.match(w):
                dbg("Skip C keyword: [%s]" % (w, ))
                continue

            # asm directives
            if rex_asm_dir.match(w):
                dbg("Skip asm directive: [%s]" % (w, ))
                continue

            # sections
            if rex_sections.match(w):
                dbg("Skip section name: [%s]" % (w, ))
                continue

            # tool options
            if rex_opts.match(w):
                dbg("Skip tool option: [%s]" % (w, ))
                continue

            # hyphenated words
            m = rex_hyphenated.match(w)
            if m:
                if dc.check(m.group(1)):
                    dbg("Skip hyphenated: [%s]-%s" % (m.group(1), m.group(2), ))

                if dc.check(m.group(2)):
                    dbg("Skip hyphenated: %s-[%s]" % (m.group(1), m.group(2), ))
                    continue

            # <word>-BLA
            m = rex_word_bla.match(w)
            if m:
                if dc.check(m.group(1)):
                    dbg("Skip <word>-BLA: [%s]" % (w, ))
                    continue

            # reference to register fields like GHCBData[55:52], for example
            if rex_reg_field.match(w):
                dbg("Skip reference to register fields: [%s]" % (w, ))
                continue

            # misc numbering with misc formatting
            if rex_misc_num.match(w):
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
            print(" [%s]\n [%s]\n" % (s, new_subj, ))

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

        rex_from = re.compile(r'^\s?From:\s?(.*)', re.I)

        for line in plines:
            # Scan for a potential new From:
            m = rex_from.match(line)
            if m:
                new_from = m.group(1)
                if new_from != self.sender:
                    self.author = new_from
                    print("Found new author: [%s]" % (new_from))
                    plines.remove(line)

        self.commit_msg = "\n".join(plines[:])

    def verify_diff(self):
        ps = unidiff.PatchSet(self.diff)

        rex_unicode_chars = re.compile(r'([^\x00-\xff])')

        # a PatchSet contains a bunch of PatchedFile's
        for pfile in ps:
            # each PatchedFile contains a bunch of Hunk's
            for hunk in pfile:
                for line in str(hunk).splitlines():
                    # check for unicode chars, aka https://trojansource.codes/
                    m = rex_unicode_chars.search(line)
                    if m:
                        warn_on(1, "Unicode char [%s] (0x%x) in line: %s"
                                % (m.group(1), ord(m.group(1)), line, ))

                spellcheck_hunk(pfile, hunk)

                # strip the first two "a/" or "b/"
                f = pfile.target_file[2:]

                verify_binutils_version(f, hunk)
                verify_comment_style(f, hunk)

    def __insert_tag(self, tag, name):
        if name in self.od[tag]:
            dbg("%s already present for tag %s, skipping" % (name, tag, ))
            return

        try:
            self.od[tag].insert(0, name)
        except KeyError:
            warn("Unknown tag: [%s: %s], ignoring it... " % (tag, name, ))

    def add_tag(self, line):
        m = re.search(r'^(.*):\s*(.*)$', line)
        if m.group(1) and m.group(2):
            info("Adding tag [%s]" % (line, ))
            self.__insert_tag(m.group(1), m.group(2))
        else:
            warn_on(1, "add_tag: Cannot match tag properly\n")

    def process_tags(self, clines):
        """
        Process tags from the commit message, backwards

        Return how many lines it ate
        """
        global sob

        ret_lines = 0

        dbg("")

        # zap any trailing empty lines
        while not clines[-1]:
            ret_lines += 1
            clines.pop()

        rex_cc_stable = re.compile(r'^\s*<stable@vger.kernel.org>\s*.*$', re.I)

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
                m = rex_cc_stable.match(name_email)
                if not m:
                    info(("Skipping Cc: %s" % (name_email, )))
                    continue

            # check Fixes: tag
            if tag.lower() == 'fixes':
                m = rex_commit_ref.match(name_email)
                if m:
                    verify_commit_ref(m.group('sha1'), m.group('commit_title'))

            info("Adding tag %s: %s" % (tag, name_email, ))
            self.__insert_tag(tag, name_email)

        # add global sob
        if sob and sob not in self.od['Signed-off-by']:
            self.od['Signed-off-by'].append(sob)

        dbg(self.od)
        dbg("done, ate %d lines" % (ret_lines, ))

        return ret_lines

    def __parse_diffstat(self, lines):
        """
        Parse and assign the diffstat from lines[]

        Return how many lines the diffstat is
        """
        ret = 0
        dfst = []

        rex_diffstat_file = re.compile(r'^.*\|\s+\d+\s+[+-]+\s?$')
        rex_diffstat_sum  = re.compile(r'^.*files?\s+changed(.*insertions?\(\+\))?(.*deletions?\(\-\))?$')
        rex_diffstat_mod  = re.compile(r'^\s+(create|delete) mode [0-9]+ .*')

        for line in lines:
            # git or quilt-type patch
            if not line or line.startswith("diff") or line.startswith("---"):
                break

            # pick out only the actual diffstat lines
            # "<filepath> | <num> +-"
            if rex_diffstat_file.match(line):
                dfst.append(line)

            # X file(s) changed, Y insertions?(+), Z deletions?(-)
            if rex_diffstat_sum.match(line):
                dfst.append(line)

            # create/delete mode
            if rex_diffstat_mod.match(line):
                dfst.append(line)

            ret += 1

        self.diffstat = "\n".join(dfst[:])

        dbg("\n" + self.diffstat)
        dbg("EOF diffstat, lines: %d" % (ret, ))

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
            # changelog history which git ignores.
            if (line == "---" or line.startswith("--- a")) and not self.commit_msg:
                tag_lines = self.process_tags(plines[0:i])

                dbg("--> Commit message")
                self.postprocess_commit_msg(plines[0:i - tag_lines])
                dbg(self.commit_msg)
                dbg("End of Commit message")

                # got commit message and tags, remove it from plines and start afresh

                # i+1 in order to skip "---" too
                # i if it is the beginning of the first hunk
                if line == "---":
                    cutoff_idx = i+1
                else:
                    cutoff_idx = i

                plines = plines[cutoff_idx:]
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

        dbg("i: %d" % (i, ))

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

        rex_pers_pronoun = re.compile(r'\W?we\W', re.I)
        rex_this_patch   = re.compile(r'(.*this\s+patch.*)', re.I)

        for i, l in enumerate(lines):

            # skip committer notes
            if l.startswith("  [ bp:"):
                continue

            warn_on(rex_pers_pronoun.search(l), ("Commit message has 'we':\n [%s]\n" % (l, )))
            warn_on(rex_this_patch.search(l),   ("Commit message has 'this patch':\n [%s]\n" % (l, )))

            if rex_sha1.search(l):
                try:
                    nxt = lines[i + 1]
                except IndexError:
                    nxt = ""

                verify_commit_quotation(i, lines[i - 1], lines[i], nxt)

        flags = { 'check_func': True }
        spellcheck(self.commit_msg, "commit message", flags)

    def format_tags(self, f, link_check=True):
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

        link_url = ""
        if self.message_id:
            link_url = ("https://lore.kernel.org/r/%s" % (self.message_id, ))
        elif od['Link']:
            link_url = od['Link'][0]
            warn("Using Link URL from patch itself: %s" % (link_url, ))
            self.message_id = link_url

        if link_check and link_url:
            try:
                get = requests.get(link_url)
                if get.status_code != 200:
                    err("Link URL %s not reachable, status_code: %d" % (link_url, get.status_code, ))
            except requests.exceptions.RequestException as e:
                err("Exception %s while trying to get URL: %s" % (e, link_url, ))

        # slap the Link at the end only if no Link present
        if not od['Link']:
            info(("Link: %s\n" % (link_url, )))
            f.write(("Link: %s\n" % (link_url, )))

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

    def format_patch(self, link_check):
        """
        Write patch to tmp_dir after having processed it properly

        @link_check: Check Link URL, pass to format_tags()
        """

        global tmp_dir

        if not tmp_dir:
            warn_on(1, "Output tmp_dir not set")
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
        self.format_tags(f_out, link_check)

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

    rex_asm_volatile = re.compile(r'^\s?\+\s?asm(\svolatile)?\s?\(')
    rex_dot_byte     = re.compile(r'^\s?\+.*\.byte(\s[x0-9a-f,])+',  re.I)

    for l in h.target_lines():
        line = str(l)

        # first, scan for the asm volatile() statement
        m = rex_asm_volatile.match(line)
        if m:
            inline_asm = True
            asm_line = l

        # now, scan for the .byte directive
        if inline_asm:
            m = rex_dot_byte.match(line)
            if m:
                opcodes = True
                break

        # buffer containing past lines, the comment must be in there, if at all
        lines.append(line)

    if not opcodes: return

    rex_binutils = re.compile(r'^.*binutils\s[\d.]+.*')

    for l in lines:
        m = rex_binutils.match(l)
        if m:
            return

    for l in lines:
        print(l, end="")
    err("No binutils version specified over naked opcode bytes at %s:%d" % (f, asm_line.target_line_no, ))

# check comment formatting
def verify_comment_style(pfile, h):
    in_comment = False
    comment_start = None

    rex_comment_start = re.compile(r'^.*/\*\s+\w+', re.I)

    for line in h.target_lines():
        l = str(line)

        # does the comment start have chars after the '*'?
        if not in_comment:
            m = rex_comment_start.match(l)
            if m:
                in_comment = True
                comment_start = l
                continue

        if in_comment:
            warn_on(rex_comment.match(l),
                 "Multi-line comment needs to start text on the second line:\n [%s]\n" %
                 (comment_start.strip(), ))
            in_comment = False

    # check side comments only in .c/.h files
    if not pfile.endswith(('.c', '.h')): return

    # exceptions to the rule
    if "arch/x86/include/asm/cpufeatures.h" in pfile: return

    rex_tail_comment = re.compile(r'^.*[;)]\s*/\*.*$')

    for line in h.target_lines():
        # look at only added (+) lines
        if not line.is_added:
            continue

        l = str(line)

        warn_on(rex_tail_comment.match(l), "No tail comments please:\n %s:%d [%s]\n" %
             (pfile, line.target_line_no, l.strip(), ))


def verify_commit_quotation(linenum, prev, cur, nxt):
    """
    Verify if a commit is quoted properly. Args are the three lines surrounding the sha1
    """

    if not prev and not nxt and cur.startswith("  "):
        return

    warn_on(1, "line %d: [%s]" % (linenum, cur, ))
    warn_on(1, "The proper commit quotation format is:\n<newline>\n[  ]<sha1, 12 chars> (\"commit name\")\n<newline>")
###


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

    p.format_patch(not args.no_link_check)

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
        warn_on(1, "No author SOB email configured")

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

    parser.add_argument("--no-link-check",
                        action="store_true",
                        default=False,
                        help="Do not check whether the Link tag URL is accessible")

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
