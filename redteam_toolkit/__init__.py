"""Red Team Toolkit: an educational security assessment toolkit.

Modules are pure functions that take options and return a
:class:`~redteam_toolkit.models.Report`. The CLI in :mod:`redteam_toolkit.cli`
is a thin layer over them, so every module is also usable from a notebook or a
test without going through argument parsing.
"""

from .config import TOOL_NAME, VERSION
from .models import Finding, Report

__version__ = VERSION
__all__ = ["TOOL_NAME", "VERSION", "Finding", "Report", "__version__"]
