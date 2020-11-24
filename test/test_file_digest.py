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


@pytest.mark.parametrize('package', ['binary/file-signature'])
def test_signatures(tmpdir, package, digestcheck):
    output, test = digestcheck
    test.check(get_tested_package(package, tmpdir))
    out = output.print_results(output.results)
    assert len(output.results) == 3
    assert 'E: cron-file-digest-mismatch /etc/cron.daily/suse.de-sarg expected:d536dc68e198189149048a907ea6d56a7ee9fc732ae8fec5a4072ad06640e359 has:edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb' in out
    assert 'E: cron-file-digest-unauthorized /etc/cron.daily/test-me' in out
    assert 'E: cron-file-digest-ghost /etc/cron.daily/test-me-ghost' in out
