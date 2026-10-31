"""Check Python/Bash syntax, reading the index for pre-commit checks."""
import argparse
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--staged", action="store_true")
args = parser.parse_args()


def git(*arguments):
    return subprocess.check_output(["git", *arguments])


if args.staged:
    subprocess.run(["git", "diff", "--cached", "--check"], check=True)
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
else:
    subprocess.run(["git", "diff", "--check"], check=True)
    subprocess.run(["git", "diff", "--cached", "--check"], check=True)
    names = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")

checked = 0
for raw in sorted(set(names.split(b"\0")) - {b""}):
    name = raw.decode(sys.getfilesystemencoding(), errors="surrogateescape")
    path = Path(name)
    is_python = name == "mpkg" or path.suffix == ".py"
    is_shell = path.suffix == ".sh" or path.name == "PKGBUILD" or name.startswith(".githooks/")
    if not (is_python or is_shell):
        continue
    if not args.staged and not path.is_file():
        continue  # A tracked file may have been removed in the worktree.
    content = git("show", f":{name}") if args.staged else path.read_bytes()
    if is_python:
        compile(content, name, "exec")
    else:
        result = subprocess.run(["bash", "-n"], input=content, capture_output=True)
        if result.returncode:
            sys.stderr.write(f"{name}: {result.stderr.decode(errors='replace')}")
            sys.exit(result.returncode)
    checked += 1
print(f"Syntax checked: {checked} files ({'index' if args.staged else 'worktree'}).")
