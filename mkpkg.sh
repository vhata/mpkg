#!/usr/bin/env bash

if [ -z "$3" ] ; then
  echo "Usage: $0 METAPKG_NAME DESC [ PKG .. ]"
  exit 1
fi

if [[ ! "$1" =~ ^[a-z0-9][a-z0-9_+-]*$ ]]; then
  echo "Invalid package name: use lowercase letters, digits, underscores, plus signs, or hyphens; start with a letter or digit." >&2
  exit 1
fi

METAPKG_NAME="vhata-${1#vhata-}"
DESC="$2"
shift ; shift

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

(
  cd "$METAPKG_NAME" || exit
  makepkg -si
) || exit $?
sudo pacman -D --asdeps "$@"
