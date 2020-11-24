import hashlib
from pathlib import Path
import stat

from rpmlint.checks.AbstractCheck import AbstractCheck


class FileDigestCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.digest_groups = {}
        for group, values in self.config.configuration['FileDigestLocation'].items():
            self.digest_groups[group] = [Path(p) for p in values['Locations']]

        self.package_digests = {}
        for package, issues in self.config.configuration['FileDigestGroup'].items():
            self.package_digests[package] = {}
            for value in issues.values():
                for path, digest in value['digests'].items():
                    if self._get_digest_group_from_path(path) is None:
                        raise Exception(f'Invalid digest location {path}')
                    self.package_digests[package].setdefault(path, []).append(digest)

    def _get_digest_group_from_path(self, path):
        path = Path(path)
        for group, locations in self.digest_groups.items():
            for location in locations:
                try:
                    if path.relative_to(location):
                        return group
                except ValueError:
                    pass
        return None

    def check_binary(self, pkg):
        """
        TODO: add comment
        """
        known_digests = self.package_digests.get(pkg.name)
        for filename, pkgfile in pkg.files.items():
            group = self._get_digest_group_from_path(filename)
            if not group:
                continue
            if stat.S_ISDIR(pkgfile.mode):
                continue
            elif stat.S_ISLNK(pkgfile.mode) and group:
                self.output.add_info('W', pkg, f'{group}-file-symlink', filename)
                continue

            if filename in pkg.ghost_files:
                self.output.add_info('E', pkg, f'{group}-file-digest-ghost', filename)
            elif known_digests and filename in known_digests:
                expected_digests = known_digests[filename]
                if 'skip' in expected_digests:
                    pass
                else:
                    h = hashlib.new('sha256')
                    with open(pkgfile.path, 'rb') as fd:
                        while True:
                            chunk = fd.read(4096)
                            if not chunk:
                                break
                            h.update(chunk)
                    hexdigest = h.hexdigest()
                    if hexdigest not in expected_digests:
                        self.output.add_info('E', pkg, f'{group}-file-digest-mismatch', filename,
                                             f'expected:{",".join(expected_digests)}', f'has:{hexdigest}')
            elif group:
                self.output.add_info('E', pkg, f'{group}-file-digest-unauthorized', filename)
