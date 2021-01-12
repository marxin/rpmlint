import pytest
from rpmlint.checks.FileMetadataCheck import FileMetadataCheck
from rpmlint.filter import Filter

from Testing import CONFIG, get_tested_package


@pytest.fixture(scope='function', autouse=True)
def metadatacheck():
    CONFIG.info = True
    output = Filter(CONFIG)
    test = FileMetadataCheck(CONFIG, output)
    return output, test


@pytest.mark.parametrize('package', ['binary/file-signature-good'])
def test_signatures(tmpdir, package, metadatacheck):
    output, test = metadatacheck
    test.check(get_tested_package(package, tmpdir))
    out = output.print_results(output.results)
    assert 'E: permissions-incorrect-mode /etc/cron.daily/test-me expected:crw-rw---- has:-rw-r--r--' in out
    assert 'E: permissions-incorrect-group /etc/cron.daily/test-me expected:tty has:' in out
    assert 'E: permissions-incorrect-device-minor /etc/cron.daily/test-me expected:12 has:' in out
    assert 'E: permissions-incorrect-device-major /etc/cron.daily/test-me expected:55 has:' in out
