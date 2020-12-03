import pytest
from rpmlint.checks.FileDigestCheck import FileDigestCheck
from rpmlint.filter import Filter

from Testing import CONFIG, get_tested_package


@pytest.fixture(scope='function', autouse=True)
def digestcheck():
    CONFIG.info = True
    output = Filter(CONFIG)
    test = FileDigestCheck(CONFIG, output)
    return output, test


@pytest.mark.parametrize('package', ['binary/file-signature-good'])
def test_signatures(tmpdir, package, digestcheck):
    output, test = digestcheck
    test.check(get_tested_package(package, tmpdir))
    out = output.print_results(output.results)
    assert not out


@pytest.mark.parametrize('package', ['binary/file-signature-symlinks'])
def test_signatures_symlinks(tmpdir, package, digestcheck):
    output, test = digestcheck
    test.check(get_tested_package(package, tmpdir))
    out = output.print_results(output.results)
    assert len(output.results) == 2
    assert 'file-signature-symlinks.x86_64: E: cron-file-symlink /etc/cron.daily/symlink' in out
    assert 'file-signature-symlinks.x86_64: E: cron-file-digest-ghost /etc/cron.daily/test-me-ghost' in out


@pytest.mark.parametrize('package', ['binary/file-signature-bad'])
def test_signatures_bad(tmpdir, package, digestcheck):
    output, test = digestcheck
    test.check(get_tested_package(package, tmpdir))
    out = output.print_results(output.results)
    assert len(output.results) == 2
    assert 'file-signature-bad.x86_64: E: cron-file-digest-unauthorized /etc/cron.daily/suse.de-sarg' in out
    assert 'file-signature-bad.x86_64: E: cron-file-digest-unauthorized /etc/cron.daily/test-me' in out
