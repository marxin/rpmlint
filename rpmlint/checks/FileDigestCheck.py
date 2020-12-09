import hashlib
from pathlib import Path
import stat

from rpmlint.checks.AbstractCheck import AbstractCheck


class FileDigestCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.digest_configurations = {}
        self.follow_symlinks_in_group = {}
        for group, values in self.config.configuration['FileDigestLocation'].items():
            self.digest_configurations[group] = [Path(p) for p in values['Locations']]
            self.follow_symlinks_in_group[group] = values['FollowSymlinks']

        self.digest_groups = [fd['digests'] for fd in self.config.configuration['FileDigestGroup'] if 'digests' in fd]
        for digest_group in self.digest_groups:
            # verify digest algorithm
            for digest in digest_group.values():
                algorithm = digest['algorithm']
                if algorithm == 'skip':
                    pass
                else:
                    hashlib.new(algorithm)
        self.digest_cache = {}
        self.digest_configuration_group_cache = {}

    def _get_digest_configuration_group_no_cache(self, path):
        path = Path(path)
        for group, locations in self.digest_configurations.items():
            for location in locations:
                try:
                    if path.relative_to(location):
                        return group
                except ValueError:
                    pass
        return None

    def _get_digest_configuration_group(self, pkgfile):
        if stat.S_ISDIR(pkgfile.mode):
            return None
        if pkgfile.name not in self.digest_configuration_group_cache:
            gr = self._get_digest_configuration_group_no_cache(pkgfile.name)
            self.digest_configuration_group_cache[pkgfile.name] = gr
        return self.digest_configuration_group_cache[pkgfile.name]

    def _check_filetypes(self, pkg):
        """
        Check that all symlinks point to a correct location and that
        symlinks are allowed in a configuration group.
        """
        result = True
        for filename, pkgfile in pkg.files.items():
            group = self._get_digest_configuration_group(pkgfile)
            if not group:
                continue

            if filename in pkg.ghost_files:
                self.output.add_info('E', pkg, f'{group}-file-digest-ghost', filename)
                result = False
                continue

            if stat.S_ISLNK(pkgfile.mode) and not self.follow_symlinks_in_group[group]:
                self.output.add_info('E', pkg, f'{group}-file-symlink', filename)
                result = False
                continue
        return result

    def _is_valid_digest(self, pkgfile, digest, pkg):
        algorithm = digest['algorithm']
        if algorithm == 'skip':
            return True

        while stat.S_ISLNK(pkgfile.mode):
            pkgfile = pkg.readlink(pkgfile)
            if not pkgfile:
                return False

        digest_hash = digest['hash']
        pair = (pkgfile.name, algorithm)
        if pair not in self.digest_cache:
            h = hashlib.new(algorithm)
            with open(pkgfile.path, 'rb') as fd:
                while True:
                    chunk = fd.read(4096)
                    if not chunk:
                        break
                    h.update(chunk)
            self.digest_cache[pair] = h.hexdigest()

        return self.digest_cache[pair] == digest_hash

    def _check_group_digests(self, digest_group, pkg):
        for filename, digest in digest_group.items():
            if not self._is_valid_digest(pkg.files[filename], digest, pkg):
                return False
        return True

    def check_binary(self, pkg):
        """
        Check that all files in secured locations are covered by a file digest group
        in which all files have valid digest.
        """

        if not self._check_filetypes(pkg):
            return

        # First collect all files that are in a digest configuration group
        secured_paths = {pkgfile.name for pkgfile in pkg.files.values() if self._get_digest_configuration_group(pkgfile)}

        # Iterate all digest groups and find one that covers all secured files
        # and in which all digests match
        for digest_group in self.digest_groups:
            covered_files = set(digest_group.keys())
            if secured_paths - covered_files:
                # bail out as some secured paths are not covered
                continue
            elif covered_files - set(pkg.files.keys()):
                # a group has a digest for a file that is not in the package
                continue
            elif self._check_group_digests(digest_group, pkg):
                # we are done, we found a valid group
                return

        # Report errors
        for filename in sorted(secured_paths):
            group = self._get_digest_configuration_group(pkg.files[filename])
            self.output.add_info('E', pkg, f'{group}-file-digest-unauthorized', filename)