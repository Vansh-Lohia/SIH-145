import sys
from pathlib import Path

# Make the src-layout package importable without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
