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
    assert not out
