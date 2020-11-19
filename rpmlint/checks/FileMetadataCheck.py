import os
from pathlib import Path
import stat

from rpmlint.checks.AbstractCheck import AbstractCheck


class FileMetadataCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.metadata = {}
        for values in self.config.configuration['FileMetadataCheck'].values():
            for path, meta in values['metadata'].items():
                self.metadata[path] = meta

    def check_binary(self, pkg):
        """
        TODO: add comment
        """
        for filename, pkgfile in pkg.files.items():
            if filename in self.metadata:
                path = Path(pkgfile.path)
                path_stat = path.stat()
                meta = self.metadata[filename]

                if 'mode' in meta:
                    mode = stat.filemode(path_stat.st_mode)
                    if mode != meta['mode']:
                        self.output.add_info('E', pkg, 'permissions-incorrect-mode', filename,
                                             f'expected:{meta["mode"]}', f'has:{mode}')
                if 'owner' in meta:
                    owner = path.owner()
                    if owner != meta['owner']:
                        self.output.add_info('E', pkg, 'permissions-incorrect-owner', filename,
                                             f'expected:{meta["owner"]}', f'has:{owner}')
                if 'group' in meta:
                    group = path.group()
                    if group != meta['group']:
                        self.output.add_info('E', pkg, 'permissions-incorrect-group', filename,
                                             f'expected:{meta["group"]}', f'has:{group}')
                if 'device_minor' in meta:
                    device_minor = os.minor(path_stat.st_dev)
                    if device_minor != meta['device_minor']:
                        self.output.add_info('E', pkg, 'permissions-incorrect-device-minor', filename,
                                             f'expected:{meta["device_minor"]}', f'has:{device_minor}')
                if 'device_major' in meta:
                    device_major = os.major(path_stat.st_dev)
                    if device_major != meta['device_major']:
                        self.output.add_info('E', pkg, 'permissions-incorrect-device-major', filename,
                                             f'expected:{meta["device_major"]}', f'has:{device_major}')
