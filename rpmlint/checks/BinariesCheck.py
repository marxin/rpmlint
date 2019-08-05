#############################################################################
# File          : BinariesCheck.py
# Package       : rpmlint
# Author        : Frederic Lepied
# Created on    : Tue Sep 28 07:01:42 1999
# Purpose       : check binary files in a binary rpm package.
#############################################################################

from pathlib import Path
import re
import stat

import rpm
from rpmlint import pkg as Pkg
from rpmlint.checks.AbstractCheck import AbstractCheck
from rpmlint.lddparser import LddParser
from rpmlint.readelfparser import ReadelfParser
from rpmlint.stringsparser import StringsParser


def create_nonlibc_regexp_call(call):
    r = r'.*?\s+UND\s+(%s)\s?.*$' % call
    return re.compile(r)


class BinaryInfo(object):

    call_regex = re.compile(r'\s0\s+FUNC\s+(.*)')

    def __init__(self, config, output, pkg, path, fname, is_ar, is_shlib):
        self.readelf_error = False
        self.config = config
        self.output = output
        self.forbidden_calls = []

        self.forbidden_functions = self.config.configuration['WarnOnFunction']
        if self.forbidden_functions:
            for name, func in self.forbidden_functions.items():
                # precompile regexps
                f_name = func['f_name']
                func['f_regex'] = create_nonlibc_regexp_call(f_name)
                if 'good_param' in func and func['good_param']:
                    func['waiver_regex'] = re.compile(func['good_param'])
                # register descriptions
                self.output.error_details.update({name: func['description']})

        res = Pkg.getstatusoutput(
            ('readelf', '-W', '-S', '-l', '-d', '-s', path))
        if not res[0]:
            lines = res[1].splitlines()

            for line in lines:
                if line.startswith('Symbol table'):
                    break

            for line in lines:
                r = self.call_regex.search(line)
                if not r:
                    continue
                line = r.group(1)

                if self.forbidden_functions:
                    for r_name, func in self.forbidden_functions.items():
                        ret = func['f_regex'].search(line)
                        if ret:
                            self.forbidden_calls.append(r_name)

            # check if we don't have a string that will automatically
            # waive the presence of a forbidden call
            if self.forbidden_calls:
                res = Pkg.getstatusoutput(('strings', path))
                if not res[0]:
                    for line in res[1].splitlines():
                        # as we need to remove elements, iterate backwards
                        for i in range(len(self.forbidden_calls) - 1, -1, -1):
                            func = self.forbidden_calls[i]
                            f = self.forbidden_functions[func]
                            if 'waiver_regex' not in f:
                                continue
                            r = f['waiver_regex'].search(line)
                            if r:
                                del self.forbidden_calls[i]
        else:
            self.readelf_error = True
            # Go and others are producing ar archives that don't have ELF
            # headers, so don't complain about it
            if not is_ar:
                self.output.add_info('E', pkg, 'binaryinfo-readelf-failed',
                                     fname, re.sub('\n.*', '', res[1]))


numeric_dir_regex = re.compile(r'/usr(?:/share)/man/man./(.*)\.[0-9](?:\.gz|\.bz2)')
versioned_dir_regex = re.compile(r'[^.][0-9]')
so_regex = re.compile(r'/lib(64)?/[^/]+\.so(\.[0-9]+)*$')
bin_regex = re.compile(r'^(/usr(/X11R6)?)?/s?bin/')
reference_regex = re.compile(r'\.la$|^/usr/lib(64)?/pkgconfig/')
srcname_regex = re.compile(r'(.*?)-[0-9]')
invalid_dir_ref_regex = re.compile(r'/(home|tmp)(\W|$)')
usr_arch_share_regex = re.compile(r'/share/.*/(?:x86|i.86|x86_64|ppc|ppc64|s390|s390x|ia64|m68k|arm|aarch64|mips|riscv)')


def create_regexp_call(call):
    r = r'(%s(?:@GLIBC\S+)?)(?:\s|$)' % call
    return re.compile(r)


class BinariesCheck(AbstractCheck):

    validso_regex = re.compile(r'(\.so\.\d+(\.\d+)*|\d\.so)$')
    soversion_regex = re.compile(r'.*?([0-9][.0-9]*)\.so|.*\.so\.([0-9][.0-9]*).*')
    usr_lib_regex = re.compile(r'^/usr/lib(64)?/')
    ldso_soname_regex = re.compile(r'^ld(-linux(-(ia|x86_)64))?\.so')
    ocaml_mixed_regex = re.compile(r'^Caml1999X0\d\d$')

    setgid_call_regex = create_regexp_call(r'set(?:res|e)?gid')
    setuid_call_regex = create_regexp_call(r'set(?:res|e)?uid')
    setgroups_call_regex = create_regexp_call(r'(?:ini|se)tgroups')
    mktemp_call_regex = create_regexp_call('mktemp')

    def __init__(self, config, output):
        super().__init__(config, output)
        self.files = {}
        self.is_exec = False
        self.is_shobj = False
        # add the dictionary content
        self.output.error_details.update(binaries_details_dict)
        self.system_lib_paths = config.configuration['SystemLibPaths']
        pie_exec_re = config.configuration['PieExecutables']
        if not pie_exec_re:
            pie_exec_re = ''
        self.pie_exec_re = re.compile(pie_exec_re)
        self.usr_lib_exception_regex = re.compile(config.configuration['UsrLibBinaryException'])

        # register all check functions
        self.check_functions = [self._check_lto_section,
                                self._check_no_text_in_archive,
                                self._check_executable_stack,
                                self._check_shared_library,
                                self._check_security_functions,
                                self._check_rpath,
                                self._check_library_dependency,
                                self._check_ocaml_mixed]

    # For an archive, test if any .text sections is empty
    def _check_no_text_in_archive(self, pkg, path):
        if self.readelf_parser.is_archive:
            for elf_file in self.readelf_parser.section_info.elf_files:
                code_in_text = False
                for section in elf_file:
                    if section.name.startswith('.text') and section.size > 0:
                        code_in_text = True
                        break
                if not code_in_text:
                    self.output.add_info('E', pkg, 'lto-no-text-in-archive', path)
                    return

    # Check for LTO sections
    def _check_lto_section(self, pkg, path):
        for elf_file in self.readelf_parser.section_info.elf_files:
            for section in elf_file:
                if '.gnu.lto_.' in section.name:
                    self.output.add_info('E', pkg, 'lto-bytecode', path)
                    return

    def _check_executable_stack(self, pkg, path):
        if not self.readelf_parser.is_archive:
            stack_headers = [h for h in self.readelf_parser.program_header_info.headers if h.name == 'GNU_STACK']
            if len(stack_headers) == 0:
                self.output.add_info('E', pkg, 'missing-PT_GNU_STACK-section', path)
            elif 'E' in stack_headers[0].flags:
                self.output.add_info('E', pkg, 'executable-stack', path)

    def _check_soname_symlink(self, pkg, file_path, soname):
        path = Path(file_path)
        symlink = path.parent / soname
        try:
            # check that we have a symlink with the soname in the package
            # and it points to the checked shared library
            link = pkg.files()[str(symlink)].linkto
            if link not in (file_path, path.parent, ''):
                self.output.add_info('E', pkg, 'invalid-ldconfig-symlink', file_path, link)
        except KeyError:
            # if we do not have a symlink, report an issue
            if path.name.startswith('lib') or path.name.startswith('ld-'):
                self.output.add_info('E', pkg, 'no-ldconfig-symlink', file_path)

    def _check_shared_library(self, pkg, path):
        if not self.readelf_parser.is_shlib:
            return
        soname = self.readelf_parser.dynamic_section_info.soname
        if not soname:
            self.output.add_info('W', pkg, 'no-soname', path)
        else:
            if not self.validso_regex.search(soname):
                self.output.add_info('E', pkg, 'invalid-soname', path, soname)
            else:
                self._check_soname_symlink(pkg, path, soname)

                res = self.soversion_regex.search(soname)
                if res:
                    soversion = res.group(1) or res.group(2)
                    if soversion and soversion not in pkg.name:
                        self.output.add_info('E', pkg, 'incoherent-version-in-name', soversion)

        if not self.readelf_parser.section_info.pic:
            self.output.add_info('E', pkg, 'shlib-with-non-pic-code', path)

        if not self.readelf_parser.is_archive and not self.readelf_parser.is_debug:
            # It could be useful to check these for others than shared
            # libs only, but that has potential to generate lots of
            # false positives and noise.
            for symbol in self.ldd_parser.undefined_symbols:
                self.output.add_info('W', pkg, 'undefined-non-weak-symbol', path, symbol)
            for dependency in self.ldd_parser.unused_dependencies:
                self.output.add_info('W', pkg, 'unused-direct-shlib-dependency',
                                     path, dependency)

    def _check_security_functions(self, pkg, path):
        setgid = any(self.readelf_parser.symbol_table_info.get_functions_for_regex(self.setgid_call_regex))
        setuid = any(self.readelf_parser.symbol_table_info.get_functions_for_regex(self.setuid_call_regex))
        setgroups = any(self.readelf_parser.symbol_table_info.get_functions_for_regex(self.setgroups_call_regex))
        mktemp = any(self.readelf_parser.symbol_table_info.get_functions_for_regex(self.mktemp_call_regex))

        if setgid and setuid and not setgroups:
            self.output.add_info('E', pkg, 'missing-call-to-setgroups-before-setuid', path)

        if mktemp:
            self.output.add_info('E', pkg, 'call-to-mktemp', path)

    def _check_rpath(self, pkg, path):
        for runpath in self.readelf_parser.dynamic_section_info.runpath:
            if runpath in self.system_lib_paths or not self.usr_lib_regex.search(runpath):
                self.output.add_info('E', pkg, 'binary-or-shlib-defines-rpath', path, runpath)
                return

    def _check_library_dependency(self, pkg, path):
        dyn_section = self.readelf_parser.dynamic_section_info
        if not len(dyn_section.needed) and not (dyn_section.soname and
                                                self.ldso_soname_regex.search(dyn_section.soname)):
            if self.is_shobj:
                self.output.add_info('E', pkg,
                                     'shared-lib-without-dependency-information',
                                     path)
            else:
                self.output.add_info('E', pkg, 'statically-linked-binary', path)

        else:
            # linked against libc ?
            if 'libc.' not in dyn_section.runpath and \
               (not dyn_section.soname or
                ('libc.' not in dyn_section.soname and
                 not self.ldso_soname_regex.search(dyn_section.soname))):

                found_libc = False
                for lib in dyn_section.needed:
                    if 'libc.' in lib:
                        found_libc = True
                        break

                if not found_libc:
                    if self.is_shobj:
                        self.output.add_info('E', pkg, 'library-not-linked-against-libc',
                                             path)
                    else:
                        self.output.add_info('E', pkg, 'program-not-linked-against-libc',
                                             path)

    def _check_ocaml_mixed(self, pkg, path):
        strings = self.strings_parser.strings
        if len(strings) and self.ocaml_mixed_regex.search(strings[-1]):
            self.output.add_info('W', pkg, 'ocaml-mixed-executable', path)

    def run_elf_checks(self, pkg, pkgfile_path, path):
        self.readelf_parser = ReadelfParser(pkgfile_path, path)
        if self.readelf_parser.parsing_failed():
            self.output.add_info('E', pkg, 'binaryinfo-readelf-failed', path)
            return

        if not self.readelf_parser.is_archive:
            self.ldd_parser = LddParser(pkgfile_path, path)
            if self.ldd_parser.parsing_failed:
                self.output.add_info('E', pkg, 'binaryinfo-ldd-failed', path)
                return

        self.strings_parser = StringsParser(pkgfile_path)
        if self.strings_parser.parsing_failed:
            self.output.add_info('E', pkg, 'binaryinfo-strings-failed', path)
            return

        for fn in self.check_functions:
            fn(pkg, path)

    def check_binary(self, pkg):
        self.files = pkg.files()
        exec_files = []
        has_lib = False
        binary = False
        binary_in_usr_lib = False
        has_usr_lib_file = False
        file_in_lib64 = False

        multi_pkg = False
        srpm = pkg[rpm.RPMTAG_SOURCERPM]
        if srpm:
            res = srcname_regex.search(srpm)
            if res:
                multi_pkg = (pkg.name != res.group(1))

        for fname, pkgfile in self.files.items():

            if not stat.S_ISDIR(pkgfile.mode) and self.usr_lib_regex.search(fname):
                has_usr_lib_file = True
                if not binary_in_usr_lib and \
                        self.usr_lib_exception_regex.search(fname):
                    # Fake that we have binaries there to avoid
                    # only-non-binary-in-usr-lib false positives
                    binary_in_usr_lib = True

            if stat.S_ISREG(pkgfile.mode) and \
                    (fname.startswith('/usr/lib64') or fname.startswith('/lib64')):
                file_in_lib64 = True

            # 'is binary' stuff borrowed from https://pypi.python.org/pypi/binaryornot
            # TODO: switch to it sometime later instead of embedding our own copy
            is_elf = pkgfile.magic.startswith('ELF ')
            is_ar = 'current ar archive' in pkgfile.magic
            is_ocaml_native = 'Objective caml native' in pkgfile.magic
            is_lua_bytecode = 'Lua bytecode' in pkgfile.magic
            is_shell = 'shell script' in pkgfile.magic
            is_binary = is_elf or is_ar or is_ocaml_native or is_lua_bytecode

            if is_shell:
                file_start = None
                try:
                    with open(pkgfile.path, 'rb') as inputf:
                        file_start = inputf.read(2048)
                except IOError:
                    pass
                if (file_start and b'This wrapper script should never '
                        b'be moved out of the build directory' in file_start):
                    self.output.add_info('E', pkg, 'libtool-wrapper-in-package', fname)

            if not is_binary:
                if reference_regex.search(fname):
                    lines = pkg.grep(invalid_dir_ref_regex, fname)
                    if lines:
                        self.output.add_info('E', pkg, 'invalid-directory-reference', fname,
                                             '(line %s)' % ', '.join(lines))
                continue

            # binary files only from here on
            binary = True

            if has_usr_lib_file and not binary_in_usr_lib and \
                    self.usr_lib_regex.search(fname):
                binary_in_usr_lib = True

            if pkg.arch == 'noarch':
                self.output.add_info('E', pkg,
                                     'arch-independent-package-contains-binary-or-object',
                                     fname)
                continue

            # arch dependent packages only from here on

            # in /usr/share ?
            if fname.startswith('/usr/share/') and not usr_arch_share_regex.search(fname):
                self.output.add_info('E', pkg, 'arch-dependent-file-in-usr-share', fname)

            # in /etc ?
            if fname.startswith('/etc/'):
                self.output.add_info('E', pkg, 'binary-in-etc', fname)

            if is_ocaml_native or is_lua_bytecode or fname.endswith('.o') or \
                    fname.endswith('.static'):
                continue

            # stripped ?
            if 'not stripped' in pkgfile.magic:
                self.output.add_info('W', pkg, 'unstripped-binary-or-object', fname)

            self.is_exec = 'executable' in pkgfile.magic
            self.is_shobj = 'shared object' in pkgfile.magic
            is_pie_exec = 'pie executable' in pkgfile.magic

            # run ELF checks
            self.run_elf_checks(pkg, pkgfile.path, fname)

            # inspect binary file
            is_shlib = self.readelf_parser.is_shlib
            bin_info = BinaryInfo(self.config, self.output, pkg, pkgfile.path, fname, is_ar, is_shlib)

            if is_shlib:
                has_lib = True

            for ec in bin_info.forbidden_calls:
                self.output.add_info('W', pkg, ec, fname, bin_info.forbidden_functions[ec]['f_name'])

            if not self.is_exec and not self.is_shobj:
                continue

            if self.is_shobj and not self.is_exec and '.so' not in fname and \
                    bin_regex.search(fname):
                # pkgfile.magic does not contain 'executable' for PIEs
                self.is_exec = True

            if self.is_exec:

                if bin_regex.search(fname):
                    exec_files.append(fname)

                if ((not self.is_shobj and not is_pie_exec) and
                        self.pie_exec_re and self.pie_exec_re.search(fname)):
                    self.output.add_info('E', pkg, 'non-position-independent-executable',
                                         fname)

            if bin_info.readelf_error:
                continue

        if has_lib:
            for f in exec_files:
                self.output.add_info('E', pkg, 'executable-in-library-package', f)
            for f in self.files:
                res = numeric_dir_regex.search(f)
                fn = res and res.group(1) or f
                if f not in exec_files and not so_regex.search(f) and \
                        not versioned_dir_regex.search(fn):
                    self.output.add_info('E', pkg, 'non-versioned-file-in-library-package', f)

        if not binary and not multi_pkg and not file_in_lib64 and pkg.arch != 'noarch':
            self.output.add_info('E', pkg, 'no-binary')

        if pkg.arch == 'noarch' and file_in_lib64:
            self.output.add_info('E', pkg, 'noarch-with-lib64')

        if has_usr_lib_file and not binary_in_usr_lib:
            self.output.add_info('W', pkg, 'only-non-binary-in-usr-lib')


# Add information about checks
binaries_details_dict = {
'arch-independent-package-contains-binary-or-object':
"""The package contains a binary or object file but is tagged
noarch.""",

'arch-dependent-file-in-usr-share':
"""This package installs an ELF binary in the /usr/share
 hierarchy, which is reserved for architecture-independent files.""",

'binary-in-etc':
"""This package installs an ELF binary in /etc.  Both the
FHS and the FSSTND forbid this.""",

'noarch-with-lib64':
"""This package is marked as noarch but installs files into lib64.
Not all architectures have this in path, so the package can't be
noarch.""",

'invalid-soname':
"""The soname of the library is neither of the form lib<libname>.so.<major> or
lib<libname>-<major>.so.""",

'invalid-ldconfig-symlink':
"""The symbolic link references the wrong file. It should reference
the shared library.""",

'no-ldconfig-symlink':
"""The package should not only include the shared library itself, but
also the symbolic link which ldconfig would produce. (This is
necessary, so that the link gets removed by rpm automatically when
the package gets removed, even if for some reason ldconfig would not be
run at package postinstall phase.)""",

'shlib-with-non-pic-code':
"""The listed shared libraries contain object code that was compiled
without -fPIC. All object code in shared libraries should be
recompiled separately from the static libraries with the -fPIC option.
Use the ``eu-findtextrel'' command on a library with debugging symbols
to list code compiled without -fPIC.

Another common mistake that causes this problem is linking with
``gcc -Wl,-shared'' instead of ``gcc -shared''.""",

'libtool-wrapper-in-package':
"""Your package contains a libtool wrapper shell script. This
will not work. Instead of installing the libtool wrapper file run
``libtool --mode=install install -m perm <file> <dest>'' in order
to install the relinked file.""",

'binary-or-shlib-defines-rpath':
"""The binary or shared library defines `RPATH'. Usually this is a
bad thing because it hardcodes the path to search libraries and so
makes it difficult to move libraries around.  Most likely you will find a
Makefile with a line like: gcc test.o -o test -Wl,--rpath.  Also, sometimes
configure scripts provide a --disable-rpath flag to avoid this.""",

'statically-linked-binary':
"""The package installs a statically linked binary or object file.

Usually this is a packaging bug. If not, contact your rpmlint distributor
about this so that this error gets included in the exception file for rpmlint
and will not be flagged as a packaging bug in the future (or add it to your
local configuration if you installed rpmlint from the source tarball).""",

'executable-in-library-package':
"""The package mixes up libraries and executables. Mixing up these
both types of files makes upgrades quite impossible.""",

'non-versioned-file-in-library-package':
"""The package contains files in non versioned directories. This makes it
impossible to have multiple major versions of the libraries installed.
One solution can be to change the directories which contain the files
to subdirs of /usr/lib/<name>-<version> or /usr/share/<name>-<version>.
Another solution can be to include a version number in the file names
themselves.""",

'incoherent-version-in-name':
"""The package name should contain the major version of the library.""",

'invalid-directory-reference':
'This file contains a reference to /tmp or /home.',

'no-binary':
"""The package should be of the noarch architecture because it doesn't contain
any binaries.""",

# http://sources.redhat.com/ml/libc-alpha/2003-05/msg00034.html
'undefined-non-weak-symbol':
"""The binary contains undefined non-weak symbols.  This may indicate improper
linkage; check that the binary has been linked as expected.""",

# http://www.redhat.com/archives/fedora-maintainers/2006-June/msg00176.html
'unused-direct-shlib-dependency':
"""The binary contains unused direct shared library dependencies.  This may
indicate gratuitously bloated linkage; check that the binary has been linked
with the intended shared libraries only.""",

'only-non-binary-in-usr-lib':
"""There are only non binary files in /usr/lib so they should be in
/usr/share.""",

'binaryinfo-readelf-failed':
"""Executing readelf on this file failed, all checks could not be run.""",

'binaryinfo-tail-failed':
"""Reading trailing bytes of this file failed, all checks could not be run.""",

'ldd-failed':
"""Executing ldd on this file failed, all checks could not be run.""",

'executable-stack':
"""The binary declares the stack as executable.  Executable stack is usually an
error as it is only needed if the code contains GCC trampolines or similar
constructs which uses code on the stack.  One common source for needlessly
executable stack cases are object files built from assembler files which
don\'t define a proper .note.GNU-stack section.""",

'missing-PT_GNU_STACK-section':
"""The binary lacks a PT_GNU_STACK section.  This forces the dynamic linker to
make the stack executable.  Usual suspects include use of a non-GNU linker or
an old GNU linker version.""",

'ocaml-mixed-executable':
"""Executables built with ocamlc -custom are deprecated.  Packagers should ask
upstream maintainers to build these executables without the -custom option.  If
this cannot be changed and the executable needs to be packaged in its current
form, make sure that rpmbuild does not strip it during the build, and on setups
that use prelink, make sure that prelink does not strip it either, usually by
placing a blacklist file in /etc/prelink.conf.d.  For more information, see
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=256900#49""",

'non-position-independent-executable':
"""This executable must be position independent.  Check that it is built with
-fPIE/-fpie in compiler flags and -pie in linker flags.""",

'missing-call-to-setgroups-before-setuid':
"""This executable is calling setuid and setgid without setgroups or
initgroups. There is a high probability this means it didn't relinquish all
groups, and this would be a potential security issue to be fixed. Seek POS36-C
on the web for details about the problem.""",

'call-to-mktemp':
"""This executable calls mktemp. As advised by the manpage (mktemp(3)), this
function should be avoided. Some implementations are deeply insecure, and there
is a race condition between the time of check and time of use (TOCTOU).
See http://capec.mitre.org/data/definitions/29.html for details, and contact
upstream to have this issue fixed.""",

'unstripped-binary-or-object':
"""This executable should be stripped from debugging symbols, in order to take
less space and be loaded faster. This is usually done automatically at
buildtime by rpm. Check the build logs and the permission on the file (some
implementations only strip if the permission is 0755).""",

'lto-bytecode':
"""This executable contains a LTO section.  LTO bytecode is not portable
and should not be distributed in static libraries or e.g. Python modules.""",

'lto-no-text-in-archive':
"""This archive does not contain a non-empty .text section.  The archive
was not created with -ffat-lto-objects option.""",
}
