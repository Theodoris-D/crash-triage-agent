import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

# Make sure the benchmark exists for the test session.
import subprocess
if not (ROOT / "benchmark" / "cases").exists():
    subprocess.run([sys.executable, str(ROOT / "benchmark" / "gen_cases.py")], check=True)
