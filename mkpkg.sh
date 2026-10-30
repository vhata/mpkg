#!/usr/bin/env bash

if [ -z "$3" ] ; then
  echo "Usage: $0 METAPKG_NAME DESC [ PKG .. ]"
  exit 1
fi

# Should remove "vhata-" if it's already at the beginning
# Should also not allow dots or slashes or other invalid package name characters
METAPKG_NAME="vhata-$1"
DESC="$2"
shift ; shift

# What if this already existed, and we bumped the pkgrel if it existed and was installed and was being updated?
mkdir -p "$METAPKG_NAME"
cat <<EOF > "${METAPKG_NAME}/PKGBUILD"
pkgname=${METAPKG_NAME}
pkgver=1
pkgrel=1
pkgdesc='${DESC}'
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
  cd "$METAPKG_NAME"
  makepkg -si
)
sudo pacman -D --asdeps "$@"
