import re

import kolega_security_scanner


def test_package_imports_and_exposes_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+([.-].+)?", kolega_security_scanner.__version__)
