from importlib.metadata import version

import kolega_security_scanner


def test_version_constant_matches_distribution_metadata():
    # __version__ is the single source of truth (hatch reads it for the build);
    # the installed distribution metadata must therefore match it.
    assert kolega_security_scanner.__version__ == version("kolega-scan")
