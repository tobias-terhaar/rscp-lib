"""Shared helpers for the test suite.

Note: ``rscp_lib/__init__.py`` re-exports the classes ``RscpConnection`` and
``RscpValue`` under the same names as the underlying submodules. That's
convenient for callers but it means ``import rscp_lib.RscpConnection as m``
yields the *class*, not the module. These helpers use ``sys.modules`` to
retrieve the actual module objects when a test needs to patch module-level
attributes.
"""

import sys


def connection_module():
    return sys.modules["rscp_lib.RscpConnection"]


def value_module():
    return sys.modules["rscp_lib.RscpValue"]
