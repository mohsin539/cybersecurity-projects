"""MobileForensicsLabPortable - entry point.

Prints a launcher. Requires: python -m pip install -r requirements.txt
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mfl import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("MFL_HOST", "127.0.0.1"),
        port=int(os.environ.get("MFL_PORT", "5000")),
        debug=os.environ.get("MFL_DEBUG", "0") == "1",
    )