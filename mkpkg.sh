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

# What if this already existed, and we bumped the pkgrel if it existed and was installed and was being updated?
mkdir -p "$METAPKG_NAME"
cat <<EOF > "${METAPKG_NAME}/PKGBUILD"
pkgname=${METAPKG_NAME}
pkgver=1
pkgrel=1
pkgdesc=$(printf '%q' "$DESC")
arch=('any')

depends=(
$(
  # I wish this could be sorted
  for p in "$@" ; do
    printf "  %s\n" "$p"
  done
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
