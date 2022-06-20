#!/usr/bin/python3

"""
vp.py - Patch verifier and massager tool
"""

# TODO (and potential ideas):
#
# Add a _verify.cfg.example config file so that the user can adjust it herself
#
# extend the function-name-needs-a-verb check to when the patch is adding a new function - there
# check the name too.
#
# - a8: switch to logging module maybe:
#   https://docs.python.org/3/howto/logging.html#logging-basic-tutorial

import re
import sys
import nltk                 # Natural language processing
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
tmp_dir = "/tmp"
sob = "Firstname Lastname <user@example.com>"
git_repo = None

### generic helpers

def __func__():
    return inspect.stack()[2][3]

def err(s):
    global args

    sys.stderr.write(f"{ __func__() }: Error: {s}\n")

    if not args.force:
        sys.exit(1)

def warn_on(cond, s):
    if cond:
        print(f"{ __func__() }: Warning: {s}")

def warn(s):
    print(f"{ __func__() }: Warning: {s}")

def __verbose_helper(s, v, v_lvl):
    if v < v_lvl:
        return

    # caller is the second function up the frame
    f = inspect.stack()[2][3]

    print(f"{f}(): {s}")

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

    dbg(f"\t|{w}|")

    # skip register field specifications
    if rex_reg_field.match(w):
        dbg(f"regf: |{w}|")
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

    dbg(f"-->\t|{w}|")

    return w

# Sanity-check a commit reference
#
# @s: the commit reference string to check
def verify_commit_ref(sha1, name):
    global git_repo

    if not git_repo:
        return

    print(f"Checking commit ref [{sha1} {name}]")

    repo = Repo(git_repo)
    git = repo.git

    # check sha1 is all hex
    try:
        int(sha1, 16)
    except ValueError as e:
        sys.stderr.write(f"verify_commit_ref: SHA1 {e}\n")
        sys.exit(1)

    # min 12 of length
    if len(sha1) < 12:
        sys.stderr.write(f"Commit sha1 ({sha1}) needs to be at least 12 chars long:\n")
        try:
            print(git.show('-s', '--pretty=format:%h (\"%s\")', sha1))
        except Exception as e:
            sys.stderr.write(f"verify_commit_ref: SHA1 len exception {e}\n")

    # check sha1 is in the repo
    try:
        git.tag('--contains', sha1)
    except Exception as e:
        sys.stderr.write(f"verify_commit_ref: SHA1 not in repo: {e}\n")
        sys.exit(1)

    # compare the commit names too
    name = name.removeprefix('("').removesuffix('")')
    commit_name = git.show('--no-patch', '--pretty=format:%s', sha1)
    if name != commit_name:
        sys.stderr.write(f"verify_commit_ref: commit name mismatch: [{name}] vs [{commit_name}]\n")
        sys.exit(1)

#
### spellchecker stuff
dc = None

# my words
dc_words = [ "ACPI", "AER", "allocator", "AMD", "AMD64",
         # that's some stupid dictionary
         "amongst", "AMX", "APEI", "arm64", "asm", "BHB",
         "binutils", "bitmask", "bitfield", "bool", "breakpoint", "brk",
         "cacheline", "CLAC", "clocksource", "CMCI", "cmdline", "Coccinelle", "codename", "config", "CPER",
         "CPPC", "CPUID", "CSM", "DCT",
         "DF", "distro", "DMA", "DIMM", "e820", "EAX", "EBDA", "ECC", "EDAC", "EHCI", "enablement",
         "ENDBR", "ENQCMD", "EPT",
         "fixup", "gcc", "GHES", "goto", "GPR", "GUID", "hotplug", "hugepage", "Hygon",
         "hypercall", "HyperV", "HV", "hwpoison", "i387", "i915", "I/O", "IBT", "IMA", "init", "inlined",
         "IRET", "IRQ",
         "kallsyms", "KASAN", "KASLR", "Kconfig", "kdump", "kexec", "kmemleak", "KVM",
         "LFENCE", "libc", "linux", "livepatch", "LSB", "lvalue", "maintainership",
         "MCE", "MDS", "MMIO", "modpost", "MOVDIR64B", "MSR", "MTRR", "NMI", "noinstr",
         "NX", "objtool", "OEM", "ok", "oneliner", "OVMF", "pahole", "pdf", "percpu", "perf", "PPIN",
         "preemptible",
         "prepend", # derived from append, not in the dictionaries
         "PTE", "ptrace",
         "PV", "PVALIDATE", "QOS", "repurposing", "RCU", "RET", "retpoline", "rFLAGS", "RTM",
         "runtime", "Ryzen",
         "selftest", "SGX", "sideband", "SIGSEGV", "Skylake", "Smatch", "SNP", "SPDX", "SRAR", "SRBDS", "STAC",
         "STI", "STLF", "stringify", "struct", "SVA", "SWAPGS", "swiotlb",
         "symtab", "Synopsys", "SYSENTER", "sysfs", "TAA", "TCC", "TDCALL", "TDGETVEINFO", "TDVMCALL", "TLB", "TODO",
         "TPM", "tracepoint", "TSC", "UC", "uncacheable", "uncore", "unmapping",
         # too late for that one to enforce even as the dictionary says it is wrong
         "untrusted", "unwinder", "userspace", "vCPU", "VERW", "VLA",
         "VMCALL", "VMCB", "VMENTER", "VMLAUNCH", "VMSA", "VMware", "vsyscall", "vTOM",
         "WBINVD", "WRMSR",
         "XCR0", "Xeon",
         "XSS", "XSTATE" ]

dc_non_words = [ "E820", "X86" ]

# prominent kernel vars, etc which get mentioned often in commit messages and comments
known_vars = [ '__BOOT_DS', 'cpumask', 'earlyprintk',
           'fpstate', 'idtentry', 'kobj_type',
           'kptr_restrict', 'libvirt', 'pt_regs',
           'ptr', 'pvops', 'set_lvt_off', 'setup_data',
           'sme_me_mask', 'sysctl_perf_event_paranoid', 'threshold_banks', 'vfio', 'virtio_gpu',
           'vmlinux', 'xfeatures' ]

# known words as regexes to avoid duplication in the list above
regexes_pats = [ r'^U?ABI$',
            r'^all(mod|yes)config$',
            r'^AP[IMU]$',
            r'^AVX(512)?(-FP16)?$',
            r'BIOS(e[sn])?', r'boot(loader|up)', r'boot_params([\.\w_]+)?$', r'BS[PS]$',
            r'^cpuinfo(_x86)?$',
            r'default_(attrs|groups)', r'^DDR([1-5])?$',
            r'^S?DRAM$',
            r'^[Ee].g.$', r'^[eE]?IBRS$', r'^E?VEX$',
            r'^F[PR]U$',
            r'^GHC(B|I)$',
            r'^HL[ET]$',
            r'^Icelake(-D)?$', r'I[DS]T', r'init(ializer|rd|ramfs)?',
            r'^(in|off)lining$',
            r'(?i)^jmp$', r'^k[cm]alloc$',
            r'^[ku]probes?$', r'S?MCA$', r'^[Mm]em(block|cpy|move|remap|set|type)$',
            r'^microarchitectur(al|e)$',
            r'MOVSB?',
            r'^param(s)?$',
            r'^([Pp]ara)?virt(ualiz(ed|ing|ation))?$',
            # embedded modifier which goes at the beginning of the regex
            r'(?i)^pasid$', r'^PCIe?$', r'PS[CP]', r'^P[MU]D$',
            r'RD(MSR|RAND|SEED)$', r'^RMP(ADJUST)?$',
            r'sev_(features|status)', r'^SEV(-(ES|SNP))?$', r'^SM[ET]$',
            r'^SM[AE]P$', r'^[Ss]pectre(_v2)*$', r'^str(lcat|tab)$',
            r'T[DS]X', r'^u(16|32|64)$', r'^UM[CL]$',
            r'^U?EFI$', r'^v?syscall$', r'^VMG?E(xit|XIT)$', r'^VM[MX]?$',
            r'^VMPL([0-3])?$', r'^x86(-(32|64))?$', r'^(Xen|XENPV)$', r'^XSAVE[CS]?$' ]

def load_spellchecker():
    global dc, regexes, regexes_pats, rex_abs_fnames, rex_amd_fam, rex_asm_dir, rex_brackets, \
rex_c_keywords, rex_c_macro, rex_comment, rex_comment_end, \
rex_commit_ref, rex_constant, rex_decimal, rex_errval, rex_fnames, rex_gpr, rex_hyphenated, \
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
    rex_amd_fam     = re.compile(r'^[Ff]?[0-9a-f]+h$')
    rex_brackets    = re.compile(r'^.*[()\[\]]+.*$')
    rex_c_keywords  = re.compile(r'#(ifdef|include)')
    rex_c_macro     = re.compile(r'^[A-Z0-9_]+$')
    rex_comment     = re.compile(r'^\+\s+\*\s+.*$', re.I)
    rex_comment_end = re.compile(r'^\+\s+\*\/')

    # a commit ref is either preceded by some uninteresting chars and a space or it begins on a
    # newline
    rex_commit_ref  = re.compile(r'^(.*\s)?(?P<sha1>[a-f0-9]{7,})\s(?P<commit_title>\(\".*\"\)).*')
    rex_constant    = re.compile(r'^~?[0-9]+(?:UL)?$')

    rex_decimal     = re.compile(r'^[0-9]+$')
    rex_errval      = re.compile(r'-E(EINVAL|EXIST|NODEV|NOMEM|OPNOTSUPP|PROBE_DEFER)')

    # match only absolute filenames, for regex simplicity
    rex_abs_fnames      = re.compile(r"""\W/                # starts with /
                                     ([\w_-]+/)+[\w_-]+     # dirname + fname up to suffix
                                     (\.(c|h|S|config))?    # filenames with no suffix too
                                     \W
                                     """,
                                     re.VERBOSE)

    # potential word and / chars ending with a filename
    rex_fnames      = re.compile(r'[\w_/-]?[\w_-]+\.(?:c|h|S|config|rst)')

    rex_gpr         = re.compile(r"""([re]?[abcd]x|     # the first 4
                                       r([89]|1[0-5])|  # the extended ones
                                       [re][ds]i|       # the other 2
                                       [re][bs]p)       # the last 2
                                        """, re.I | re.X | re.VERBOSE)

    rex_hyphenated  = re.compile(r'([\w#-]+)-([\w#-]+)')
    rex_kcmdline    = re.compile(r'^\w+=([\w,]+)?$')
    rex_kdoc_arg    = re.compile(r'^@\w+:?$')
    rex_kdoc_cmt    = re.compile(r'\+\s*/\*\*\s*')
    rex_misc_num    = re.compile(r'^#\d+$')
    rex_non_alpha   = re.compile(r'^[-]*$')
    rex_opts        = re.compile(r'^-[\w\d=-]+$')    # assumption: tool options are lowercase
    # path spec can begin on a new line
    rex_paths       = re.compile(r'(^|\s)/[\w/_\*-]+\s')

    # xx:xx, with brackets around it
    rex_reg_field   = re.compile(r'(\w+)?\[\d+(:\d+)?\]', re.I)
    rex_sections    = re.compile(r'\.(altinstr_replacement|bss|data|head|noinstr(\.text)?|text)')

    rex_sent_end    = re.compile(r"""\.((\s+)?      # catch all spaces after the end of the sentence
                                                    # as some formatters add more than one for block
                                                    # formatting
                                  ([A-Za-z]+|$))  # Either another sentence starts here or EOL.
                                  """, re.VERBOSE)

    rex_struct_mem  = re.compile(r'\w+->\w+')
    # a hex with a following commit name
    rex_sha1        = re.compile(r'[a-f0-9]{12,40}\s?\(?"\w+"\)?', re.I)
    rex_units       = re.compile(r'^(0x[0-9a-f]+|[0-9a-f]+[GMKP](i?b)?)$', re.I)
    rex_url         = re.compile(r'https?://[a-z0-9:/.-]+')
    rex_version     = re.compile(r'v\d+$', re.I)
    rex_word_bla    = re.compile(r'non-(\w+)')
    rex_word_split  = re.compile(r'(\w+)\/(\w+)')
    rex_x86_traps   = re.compile(r'^#[A-Z]{2,2}$')

    # precompile all regexes
    for pat in regexes_pats:
        regexes.append(re.compile(pat))


# heuristic: check if any of the words in @w is a verb
def function_name_has_a_verb(w):
    for i in nltk.pos_tag(nltk.word_tokenize(w.replace('_', ' ')), tagset='universal'):
        print(i)
        if i[1] == 'VERB':
            return True

    return False

def spellcheck_func_name(w):
    """
    Check a function's name

    """

    dbg(f"{w}")

    if w.endswith('()'):
        dbg(f"Skip function name: [{w}]")
        return True

    if w.endswith('[]'):
        dbg(f"Skip array name: [{w}]")
        return True

    # linker range defines, heuristic only
    if w.startswith('__start_') or w.startswith('__end_'):
           return True

    # all caps - likely a macro name
    if rex_c_macro.match(w):
        dbg(f"Skip macro name: [{w}]")
        return True

    if rex_struct_mem.match(w):
        dbg(f"Skip struct member: [{w}]")
        return True

    # heuristic: check if any of the words is a verb
    if function_name_has_a_verb(w):
            return False

    return True


regexes = []

def spellcheck_regexes(w):
    """
        Check word @w against a list of regexes of known words
    """

    for rgx in regexes:
        m = rgx.match(w)
        if m:
            dbg(f"Skip regexed word: [{w}] match: ({ m.group(0) })")
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
        if (where == "commit message" and
            (line.startswith("  ") or line.startswith("$ "))):
            continue

        # URLs - ignore them
        line = rex_url.sub('', line)

        # filenames, ditto
        line = rex_abs_fnames.sub('', line)
        line = rex_fnames.sub('', line)

        # paths... replace with a single \s because the regex is eating it
        line = rex_paths.sub(' ', line)

        # section names - no need to check those
        line = rex_sections.sub(' ', line)

        # remove fullstops ending a sentence - not other dots, as in "i.e." for example.
        line = rex_sent_end.sub(r' \1', line)

        # replace "word/word" with "word word" so that the line can be
        # split into words properly
        line = rex_word_split.sub(r'\1 \2', line)

        # '/' to split "word/word" formulations
        words = re.split(r'[\s/]', line)

        for i, w in enumerate(words):
            # remove punctuation, etc
            w = w.strip('`\',*+:;!|<>"=^')

            # remove prepended chars
            w = w.lstrip('%')

            w = strip_brackets(w)

            if not w:
                continue

            # only non-alphabetical chars left?
            if rex_non_alpha.match(w):
                dbg(f"Only non-alpha chars left: [{w}]")
                continue

            dbg(f"{where}: [{w}]")

            # bold font, for example: "_especially_"
            if w.startswith('_') and w.endswith('_'):
                w = w.lstrip('_')
                w = w.rstrip('_')

            # local asm label
            if w.startswith('.L'):
                continue

            # skip SHAs
            if rex_sha1.match(w):
                dbg(f"Skip SHA: [{w}]")
                continue

            if w.startswith("CONFIG_") or w.startswith("ARCH_"):
                dbg(f"Skip CONFIG_ item: [{w}]")
                continue

            if w in known_vars:
                dbg(f"Skip known_vars [{w}]")
                continue

            if spellcheck_regexes(w):
                continue

            # kernel cmdline params
            if rex_kcmdline.match(w):
                dbg(f"Skip cmdline param: [{w}]")
                continue

            # error value defines
            if rex_errval.match(w):
                dbg(f"Skip error define: [{w}]")
                continue

            # Check function names
            if flags and flags['check_func']:

                # it is only a heuristic anyway
                if (('_' in w or w.endswith('()'))
                        and words[i - 1] != "struct"
                        and not w.startswith('.')):
                    ret = spellcheck_func_name(w)
                    if ret:
                        continue

                    warn_on(1, (f"Function name doesn't end with (): [{w}]"))
                    print(f" [{line}]")

            # kernel-doc arguments
            if rex_kdoc_arg.match(w):
                dbg(f"Skip kernel-doc argument: [{w}]")
                continue

            # number: decimal...
            if rex_decimal.match(w):
                dbg(f"Skip decimal number: [{w}]")
                continue

            # number: hex, units, ...
            m = rex_units.match(w)
            if m:
                dbg(f"Skip hex number/unit [{w}], match [{ m.group(0) }]")
                continue

            # number: constants...
            m = rex_constant.match(w)
            if m:
                dbg(f"Skip constant number [{w}], match [{ m.group(0) }]")
                continue

            # x86 trap names
            if rex_x86_traps.match(w):
                dbg(f"Skip x86 trap name: [{w}]")
                continue

            # x86 registers
            if rex_gpr.match(w):
                dbg(f"Skip x86 register: [{w}]")
                continue

            # versions...
            if rex_version.match(w):
                dbg(f"Skip version: [{w}]")
                continue

            # C keywords
            if rex_c_keywords.match(w):
                dbg(f"Skip C keyword: [{w}]")
                continue

            # asm directives
            if rex_asm_dir.match(w):
                dbg(f"Skip asm directive: [{w}]")
                continue

            # AMD families
            if rex_amd_fam.match(w):
                dbg(f"Skip AMD family: [{w}]")
                continue

            # sections
            if rex_sections.match(w):
                dbg(f"Skip section name: [{w}]")
                continue

            # tool options
            if rex_opts.match(w):
                dbg(f"Skip tool option: [{w}]")
                continue

            # hyphenated words
            m = rex_hyphenated.match(w)
            if m:
                if dc.check(m.group(1)):
                    dbg(f"Skip hyphenated: [{ m.group(1) }]-{ m.group(2) }")

                if dc.check(m.group(2)):
                    dbg(f"Skip hyphenated: { m.group(1) }-[{ m.group(2) }]")
                    continue

            # <word>-BLA
            m = rex_word_bla.match(w)
            if m:
                if dc.check(m.group(1)):
                    dbg(f"Skip <word>-BLA: [{w}]")
                    continue

            # reference to register fields like GHCBData[55:52], for example
            if rex_reg_field.match(w):
                dbg(f"Skip reference to register fields: [{w}]")
                continue

            # misc numbering with misc formatting
            if rex_misc_num.match(w):
                dbg(f"Skip misc numbering: [{w}]")
                continue

            # skip words containing '_' - they're likely variable or function names
            if '_' in w:
                dbg(f"Skip '_'-containing word: [{w}]")
                continue

            if not dc.check(w):
                # see if it is plural or genitive: "<word>'s"
                if dc.check(w.rstrip('\'s')):
                    continue

                # gerund?
                if dc.check(w.removesuffix('ing')):
                    dbg(f"Skip gerund: [{w}]")
                    continue

                print(line)
                print(f"Unknown word [{w}] in {where}.")
                suggestions = dc.suggest(w)
                if suggestions:
                    print(f"Suggestions: {suggestions}")
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

        self.no_link_check = False
        self.no_link_tag = False

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
        info(f"Patch: orig_subject: [{self.orig_subject}]")

        self.sender  = msg['from']
        self.author = self.sender
        info(f"Patch: sender: [{self.sender}]")

        if msg['date']:
            self.date = msg['date']

        if msg['message-id']:
            self.message_id = msg['message-id'].strip('<>')

        # The whole patch as string
        self.patch = msg.get_payload()

        self.process_patch()

    def __repr__(self):
        return (
f"""Class patch:
    original subject: [{self.orig_subject}]
             subject: [{self.subject}]
              sender: [{self.sender}]
              author: [{self.author}]
             version: [{self.version}]
              number: [{self.number}]
                name: [{self.name}]
                date: [{self.date}]
          message-id: [{self.message_id}]
""")

    def massage_subject(self):
        """
        Massage original subject into submission
        """

        s = self.orig_subject

        # strip [PATCH... ], tglx sometimes sends [patch... ], how rude of him...
        s = re.sub(r'\[PATCH[^]]*\]\s?', '', s, flags=re.I)

        # remove funky newlines
        s = re.sub(r'\n', '', s)

        # fixup EDAC prefix, needs to happen before the split as it uses the ':' as a sep
        s = re.sub(r'edac:\s([a-z0-9]+)_edac:', r'EDAC/\1:', s, re.I)

        try:
            (prefix, title) = s.rsplit(':', 1)
        except ValueError:
            sys.stderr.write(f"Cannot split subject; no prefix?: [{s}]\n")
            sys.exit(1)

        # replace commas in the subject with slashes. I need to avoid replacing when it looks like
        # "x86/MCE/AMD, EDAC/amd64:"
        prefix = re.sub(r'([:alnum:]+),([:alnum:]+)', r'\1/\2', prefix)

        # uppercase "EDAC":
        prefix = re.sub(r'edac/', 'EDAC/', prefix)

        assert prefix != s, "Subject does not contain ':'"

        # capitalize first letter
        title = title.lstrip()
        new_title = title[0].upper() + title[1:]

        flags = { 'check_func': True }
        spellcheck(new_title, "Subject", flags)

        new_subj = prefix + ": " + new_title

        if s != new_subj:
            print("Massaged subject:")
            print(f" [{s}]\n [{new_subj}]\n")

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

            a = f"{first} {last} { m.group('author_email') }"

        if self.author != a:
            print(f"{ __func__() }: New author: [{a}]")
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

        dbg(f"version: [{version}]")
        dbg(f"Patch: rest: [{rest}]")

        # patch numbering
        pnum = 1
        max_pnum = 1
        m = re.match(r'\s*(?P<pnum>\d+)\/(?P<max_pnum>\d+)', rest)
        if m and m.group('pnum'):
            pnum = int(m.group('pnum'))

        if m and m.group('max_pnum'):
            max_pnum = int(m.group('max_pnum'))

        dbg(f"Patch: ver: {version}, range: {pnum}-{max_pnum}")

        # patch name
        m = re.match(r'^.*\[.*patch[^]]*\]\s*(?P<pname>.*)', self.orig_subject, re.I)
        if m and m.group('pname'):
            dbg(f"Patch: pname: [{ m.group('pname') }]")
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
                    print(f"Found new author: [{new_from}]")
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
                        warn_on(1, f"Unicode char [{ m.group(1) }] (0x{ ord(m.group(1)) } in line: {line}")

                spellcheck_hunk(pfile, hunk)

                # strip the first two "a/" or "b/"
                f = pfile.target_file[2:]

                verify_binutils_version(f, hunk)
                verify_comment_style(f, hunk)
                verify_symbol_exports(f, hunk)
                verify_include_paths(f, hunk)
                check_for_asserts(f, hunk)

    def __insert_tag(self, tag, name):
        try:
            if name in self.od[tag]:
                dbg(f"{name} already present for tag {tag}, skipping")
                return
        except KeyError:
            warn(f"Unknown tag: [{tag}: {name}], ignoring it... \n")
            return

        self.od[tag].insert(0, name)

    def add_tag(self, line):
        m = re.search(r'^(.*):\s*(.*)$', line)
        if m.group(1) and m.group(2):
            info(f"Adding tag [{line}]")
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

        # zap any uninteresting lines
        while (not clines[-1] or
                   clines[-1].startswith("index ") or
                   clines[-1].startswith("diff --git ")):
            ret_lines += 1
            clines.pop()

        rex_cc_stable = re.compile(r'^\s*<?stable@vger.kernel.org>?\s*.*$', re.I)

        for line in reversed(clines):
            # relies on the fact that tags and commit message are separated by an empty line
            if not line:
                break

            if ':' not in line:
                warn(f"skipping line: [{line}]")
                ret_lines += 1
                continue
            else:
                dbg(line)

            (a, b) = line.split(':', maxsplit=1)
            tag = a.strip()
            name_email = b.strip()

            dbg(f"--> tag: [{tag}] name: [{name_email}]")
            ret_lines += 1

            # Skip all Cc: tags except stable and explicitly added ones
            if tag.lower() == "cc":
                m = rex_cc_stable.match(name_email)
                if not m:
                    info(f"Skipping Cc: {name_email}")
                    continue

            # check Fixes: tag
            if tag.lower() == 'fixes':
                m = rex_commit_ref.match(name_email)
                if m:
                    verify_commit_ref(m.group('sha1'), m.group('commit_title'))

            info(f"Adding tag {tag}: {name_email}")
            self.__insert_tag(tag, name_email)

        # add global sob
        if sob and sob not in self.od['Signed-off-by']:
            self.od['Signed-off-by'].append(sob)

        dbg(self.od)
        dbg(f"done, ate {ret_lines} lines")

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
        dbg(f"EOF diffstat, lines: {ret}")

        return ret


    def parse_patch(self):
        """
        Go through the patch and pick apart stuff like tags, diffstat, hunks etc.
        """
        plines = self.patch.splitlines()

        for i, line in enumerate(plines):
            dbg(f" -> [{line}]")

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


        dfst_len = self.__parse_diffstat(plines)

        # remove diffstat
        plines = plines[dfst_len:]

        # skip potential sender notes etc
        for i, line in enumerate(plines):
            if line.startswith("diff") or line.startswith("---"):
                break

        dbg(f"i: {i}")

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
            err(f"Subject prefix wrong: [{ self.subject }]")

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

            warn_on(rex_pers_pronoun.search(l), f"Commit message has 'we':\n [{l}]\n")
            warn_on(rex_this_patch.search(l),   f"Commit message has 'this patch':\n [{l}]\n")

            if rex_sha1.search(l):
                try:
                    nxt = lines[i + 1]
                except IndexError:
                    nxt = ""

                verify_commit_quotation(i, lines[i - 1], lines[i], nxt)

        flags = { 'check_func': True }
        spellcheck(self.commit_msg, "commit message", flags)


    def format_tags(self, f):
        """
        @f: Write into this file stream
        """

        od = self.od
        cdb = "Co-developed-by"

        for tag in od:
            if not od[tag]:
                continue

            # handled below
            if tag == "Link":
                continue

            for v in od[tag]:
                # Slap Co-developed-by before the SOB
                if tag == 'Signed-off-by':
                    if v in od[cdb]:
                        info(f"{cdb}: {v}")
                        f.write(f"{cdb}: {v}\n")
                        od[cdb].remove(v)

                info(f"{tag}: {v}")
                f.write(f"{tag}: {v}\n")

        if self.no_link_tag:
            return

        # go through Link tags from the patch itself:
        if od['Link']:
            warn("Patch contains Link tags - select the relevant one(s):")
            for url in od['Link']:
                warn(f" Link: {url}")

                # skip previous links, add the others like bugzilla, etc refs.
                if url.startswith("https://lore.kernel.org/r/"):
                    continue

            info(f"Link: {url}")
            f.write(f"Link: {url}\n")

        if self.message_id:
            link_url = f"https://lore.kernel.org/r/{ self.message_id }"
            prefix = ""

            # check it
            if not self.no_link_check:
                try:
                    get = requests.get(link_url)
                    if get.status_code != 200:
                        err(f"Link URL { link_url } not reachable, status_code: { get.status_code }")
                except requests.exceptions.RequestException as e:
                    warn(f"Exception {e} while trying to get URL: { link_url }")
                    prefix = "URL UNVERIFIED: "

            info(f"Link: { prefix }{ link_url }\n")
            f.write(f"Link: { prefix }{ link_url }\n")

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

        @link_check: Check Link URL, pass to format_tags()
        """

        global tmp_dir

        if not tmp_dir:
            warn_on(1, "Output tmp_dir not set")
            return

        final = ("%s/%02d-%s-new.patch" % (tmp_dir, self.number, self.name, ))

        print(f"Patch: will write [{final}]")

        f_out = open(final, "w")

        self_author = f" | From: { self.author }"
        info(self_author)
        f_out.write(self_author + "\n")

        self_date = f" | Date: { self.date }"
        info(self_date)
        f_out.write(self_date + "\n")

        self_subject = f" | Subject: { self.subject }"
        info(self_subject)
        f_out.write(self_subject + "\n")

        info(" |")
        info(" | PATCH CONTENTS:")

        info(" | commit_msg:")
        info(self.commit_msg)
        f_out.write(f"{ self.commit_msg }\n")

        info(" | tags:")
        self.format_tags(f_out)

        f_out.write("---\n")

        if self.diffstat:
            info(" | diffstat:")
            info(self.diffstat)
            f_out.write(f"{ self.diffstat }")
            f_out.write("\n\n")

        info(" | diff")
        info(self.diff)
        f_out.write(f"{ self.diff }\n")

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

    rex_binutils = re.compile(r'^.*binutils\s.*[0-2]\.[0-9]+.*')
    rex_cm_start = re.compile(r'^[\s\t\+]+/\*\s+(.*)$')
    comment_string = ""
    in_comment = False

    # Fish out the comment first - binutils version spec could be spread over multiple lines
    for l in lines:
        if not in_comment:
            m = rex_cm_start.match(l)
            if m:
                in_comment = True
                comment_string += m.group(1)
        else:
            if rex_comment_end.match(l):
                break

            comment_string += re.sub(r'[+*\n]', '', l)

    dbg(f"Matching comment: [{ comment_string }]")
    m = rex_binutils.match(comment_string)
    if m:
        return

    for l in lines:
        print(l, end="")
    err(f"No binutils version specified over naked opcode bytes at {f}:{ asm_line.target_line_no }")

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
                 f"Multi-line comment needs to start text on the second line:\n [{ comment_start.strip() }]\n")
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

        warn_on(rex_tail_comment.match(l),
                f"No tail comments please:\n { pfile }:{ line.target_line_no } [{ l.strip() }]\n")

def verify_symbol_exports(pfile, h):

    rex_export_symbol = re.compile(r'^\+EXPORT_SYMBOL\W.*$')

    for line in h.target_lines():
        l = str(line)
        warn_on(rex_export_symbol.match(l),
                f"Non-GPL symbol export at { pfile }:{ line.target_line_no } [{ l.strip() }]\n")

# Check if the decompressor kernel includes kernel proper headers
def verify_include_paths(pfile, h):

    if not h.added:
        return

    if not pfile.startswith("arch/x86/boot"):
        return

    rex_include = re.compile(r'^\+#include\s+<linux/.*$')

    for line in h.target_lines():
        l = str(line)
        warn_on(rex_include.match(l),
                f"Kernel-proper include at { pfile }:{ line.target_line_no } [{ l.strip() }]\n")

# check for BUG(_ON)s
def check_for_asserts(pfile, h):
    if not h.added:
        return

    rex_bug_ons = re.compile(r'^\+.*BUG(_ON)?\(.*\).*$')

    for line in h.target_lines():
        l = str(line)
        warn_on(rex_bug_ons.match(l),
                f"Avoid BUG(_ON)s at any cost. At { pfile }:{ line.target_line_no } [{ l.strip() }]\n")

###
###


def verify_commit_quotation(linenum, prev, cur, nxt):
    """
    Verify if a commit is quoted properly. Args are the three lines surrounding the sha1
    """

    if not prev and not nxt and cur.startswith("  "):
        return

    warn_on(1, f"line {linenum}: [{cur}]")
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
        sys.stderr.write(f"Cannot access { input_file }, exiting...\n")
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

    p.no_link_check = args.no_link_check
    p.no_link_tag   = args.no_link_tag

    p.format_patch()

def parse_config_file():
    global tmp_dir, sob, git_repo

    if not os.path.exists(os.path.expanduser('~/.verify.cfg')):
        warn_on(1, "No ~/.verify.cfg configuration file found, will fallback to likely unsuitable defaults.")
        return

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

    try:
        git_repo = cfg['main']['repo']
    except:
        warn_on(1, "No git repo configured")

def init_parser():
    """ read cmdline args

        returns:
            options:dict -- config options
    """

    parser = argparse.ArgumentParser(description='patch verification and preparation script', prog='vp')

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

    parser.add_argument("--no-link-tag",
                        action="store_true",
                        default=False,
                        help="Do not add a Link tag")

    parser.add_argument("-v", "--verbose",
                        action="count",
                        help="Enable more verbose output")

    return parser.parse_args()

# fetch all NLTK resources: TODO: this should be behind a cmdline option: ./vp.py
# --refresh-helper-modules or so
def refresh_ntlk_modules():
    modules = [ 'punkt', 'averaged_perceptron_tagger', 'universal_tagset' ]

    dl = nltk.downloader.Downloader()

    for m in modules:
        try:
            if not dl.is_installed(m) or dl.is_stale(m):
                dl.download(m)
        except:
            dbg(f"cannot download ntlk module {m}")

if __name__ == '__main__':
    global args

    parse_config_file()

    args = init_parser()

    refresh_ntlk_modules()

    # check if we're in a git repo
    if not os.path.exists(os.getcwd() + "/.git"):
        os.chdir(os.path.expanduser("~") + "/kernel/linux/")
        info("Switching CWD to kernel repo.")

    main(args)
