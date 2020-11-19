import hashlib
from pathlib import Path
import stat

from rpmlint.checks.AbstractCheck import AbstractCheck


class FileSignatureCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.locations = [Path(p) for p in self.config.configuration['FileSignature']['Locations']]
        self.known_signatures = {}
        for digests in self.config.configuration['FileSignatures'].values():
            for path, digest in digests.items():
                self.known_signatures[path] = digest
                # verify algorithm
                alg = digest['algorithm']
                if alg == 'skip':
                    continue
                else:
                    hashlib.new(alg)

    def check_binary(self, pkg):
        """
        Check that all files in FileSignature.Locations have a valid signature
        that are defined in FileSignatures.
        """
        for filename, pkgfile in pkg.files.items():
            if stat.S_ISDIR(pkgfile.mode):
                continue

            if filename in pkg.ghost_files:
                self.output.add_info('E', pkg, 'file-signature-ghostfile', filename)
            elif filename in self.known_signatures:
                digest = self.known_signatures[filename]
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
                    self.output.add_info('E', pkg, 'file-signature-hash-mismatch', filename,
                                         f'expected:{digest["hash"]}', f'has:{signature}')
            else:
                path = Path(filename)
                for location in self.locations:
                    try:
                        if path.relative_to(Path(location)):
                            self.output.add_info('E', pkg, 'file-signature-unauthorized', filename)
                        break
                    except ValueError:
                        pass
