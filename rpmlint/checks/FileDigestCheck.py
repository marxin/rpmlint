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

        self.known_digests = {}
        for value in self.config.configuration['FileDigestGroup'].values():
            for path, digest in value['digests'].items():
                if self._get_digest_group_from_path(path) is None:
                    raise Exception(f'Invalid digest location {path}')
                self.known_digests[path] = digest
                # verify algorithm
                alg = digest['algorithm']
                if alg == 'skip':
                    continue
                else:
                    hashlib.new(alg)

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
        for filename, pkgfile in pkg.files.items():
            group = self._get_digest_group_from_path(filename)
            if stat.S_ISDIR(pkgfile.mode):
                continue
            elif stat.S_ISLNK(pkgfile.mode) and group:
                self.output.add_info('W', pkg, f'{group}-file-symlink', filename)
                continue

            if filename in pkg.ghost_files:
                self.output.add_info('E', pkg, f'{group}-file-digest-ghost', filename)
            elif filename in self.known_digests:
                digest = self.known_digests[filename]
                alg = digest['algorithm']

                if alg == 'skip':
                    continue

                h = hashlib.new(alg)
                with open(pkgfile.path, 'rb') as fd:
                    while True:
                        chunk = fd.read(4096)
                        if not chunk:
                            break
                        h.update(chunk)
                signature = h.hexdigest()
                if signature != digest['hash']:
                    self.output.add_info('E', pkg, f'{group}-file-digest-mismatch', filename,
                                         f'expected:{digest["hash"]}', f'has:{signature}')
            elif group:
                self.output.add_info('E', pkg, f'{group}-file-digest-unauthorized', filename)
