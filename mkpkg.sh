#!/usr/bin/env bash

if (( $# < 2 )); then
  echo "Usage: $0 METAPKG_NAME DESC PKG [ PKG .. ]"
  echo "       $0 METAPKG_NAME +PKG|-PKG [ +PKG|-PKG .. ]"
  exit 1
fi

if [[ ! "$1" =~ ^[a-z0-9][a-z0-9_+-]*$ ]]; then
  echo "Invalid package name: use lowercase letters, digits, underscores, plus signs, or hyphens; start with a letter or digit." >&2
  exit 1
fi

METAPKG_NAME="vhata-${1#vhata-}"
EDIT_MODE=false
if [[ "$2" == [+-]* ]]; then
  EDIT_MODE=true
  if [[ ! -f "${METAPKG_NAME}/PKGBUILD" ]]; then
    echo "Cannot edit: ${METAPKG_NAME}/PKGBUILD does not exist." >&2
    exit 1
  fi
  shift
else
  if (( $# < 3 )); then
    echo "Supply a description and at least one dependency." >&2
    exit 1
  fi
  DESC="$2"
  shift ; shift
fi

PKGREL=1
if [[ -f "${METAPKG_NAME}/PKGBUILD" ]]; then
  PREVIOUS_PKGREL=$(sed -n 's/^pkgrel=\([0-9][0-9]*\)$/\1/p' "${METAPKG_NAME}/PKGBUILD")
  if [[ ! "$PREVIOUS_PKGREL" =~ ^[0-9]+$ ]]; then
    echo "Cannot increment pkgrel: expected one integer pkgrel assignment in ${METAPKG_NAME}/PKGBUILD." >&2
    exit 1
  fi
  # ensure base 10 arithmetic
  PKGREL=$((10#$PREVIOUS_PKGREL + 1))
  if (( PKGREL <= 0 )); then
    echo "Cannot increment pkgrel: release number is too large." >&2
    exit 1
  fi
fi

if "$EDIT_MODE"; then
  DEPENDENCIES=$(python3 - "${METAPKG_NAME}/PKGBUILD" "$PKGREL" "$@" <<'PYEDIT'
import pathlib
import re
import shlex
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
try:
    blocks = list(re.finditer(r"^depends=\((.*?)\)", text, re.M | re.S))
    if len(blocks) != 1:
        raise ValueError("expected one literal depends array")
    block = blocks[0]
    body = block.group(1)
    # Parse literal shell words only; never execute the existing PKGBUILD.
    if any(char in body for char in "$`\\"):
        raise ValueError("depends array must contain literal package names")
    dependencies = set(shlex.split(body, comments=True))
    pattern = r"[a-zA-Z0-9_+][a-zA-Z0-9@._+:<>=~-]*"
    if any(not re.fullmatch(pattern, dep) for dep in dependencies):
        raise ValueError("unsupported dependency in existing array")
    for change in sys.argv[3:]:
        if len(change) < 2 or change[0] not in "+-" or not re.fullmatch(pattern, change[1:]):
            raise ValueError("each edit must be +PACKAGE or -PACKAGE")
        if change[0] == "+":
            dependencies.add(change[1:])
        else:
            dependencies.discard(change[1:])
    ordered = sorted(dependencies)
    replacement = "depends=(\n" + "".join("  '" + dep + "'\n" for dep in ordered) + ")"
    updated = text[:block.start()] + replacement + text[block.end():]
    updated = re.sub(r"^pkgrel=[0-9]+$", "pkgrel=" + sys.argv[2], updated, count=1, flags=re.M)
    path.write_text(updated)
    print("\n".join(ordered), end="")
except ValueError as error:
    sys.exit("Cannot edit dependencies: " + str(error))
PYEDIT
  ) || exit $?
  set --
  if [[ -n "$DEPENDENCIES" ]]; then
    mapfile -t DEPENDENCY_ARRAY <<< "$DEPENDENCIES"
    set -- "${DEPENDENCY_ARRAY[@]}"
  fi
else
mkdir -p "$METAPKG_NAME" || exit
cat <<EOF > "${METAPKG_NAME}/PKGBUILD"
pkgname=${METAPKG_NAME}
pkgver=1
pkgrel=${PKGREL}
pkgdesc=$(printf '%q' "$DESC")
arch=('any')

depends=(
$(
  printf '  %s\n' "$@" | LC_ALL=C sort
)
)

package() {
  :
}
EOF
fi

(
  cd "$METAPKG_NAME" || exit
  makepkg -si
) || exit $?
if (( $# > 0 )); then
  sudo pacman -D --asdeps "$@"
fi
