"""Make `analyst` importable when pytest is invoked as `pytest tests/`.

pytest inserts the *test file's* directory on sys.path (rootdir-relative
insertion only happens with an __init__.py package layout), so without this the
`tests/` directory shadows the repo root and `import analyst` fails. Two lines
here is cheaper than restructuring the repo into src-layout mid-project.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
