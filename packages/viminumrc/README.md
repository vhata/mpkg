# viminumrc

`viminumrc` provides a shared Vim configuration for Arch Linux, with
editing defaults, search, buffer and split navigation, and bundled
surround operations. It depends on `vim` and installs the configuration,
plugins, and usage guide under `/usr/local/etc/vimrc`.

`/etc/profile.d/viminumrc.sh` selects the configuration for login
sessions:

```sh
export VIMINIT='source /usr/local/etc/vimrc/vimrc'
```

Manage this package with makepkg and pacman as described below. It lives
under `packages/` because the existing `mpkg` helper creates and
rewrites empty metapackages; its commands are not for maintaining
payload packages.

Plugins are included in the package; building it and starting Vim
require no plugin downloads. See the
[plugin documentation](bundle-README.md) and [license](LICENSE.txt).

`README.vimrc` documents the editor's features and keybindings. It is
installed as `/usr/local/etc/vimrc/README.md`.

## Build and install

From this directory, build first without installing anything:

```sh
makepkg
```

This requires Arch's build tools and the `vim` dependency to be
installed. If makepkg reports a missing dependency, resolve it before
continuing. If `/usr/local/etc/vimrc` already exists, move it to a
backup before installing. Choose a backup name that does not already
exist, then run:

```sh
backup_dir=/usr/local/etc/vimrc.before-viminumrc
test ! -e "$backup_dir" && test ! -L "$backup_dir" &&
  sudo mv -T /usr/local/etc/vimrc "$backup_dir" &&
  sudo pacman -U ./viminumrc-1-1-any.pkg.tar.zst
```

Proceed with installation only after the move succeeds. The archive name
above uses makepkg's default compression and output directory; use the
actual built archive if your makepkg configuration changes them.
Existing unowned files would otherwise cause file conflicts. Do not use
`--overwrite` to discard them. If installation fails, restore the saved
configuration directory while the installation destination is absent.

Package installation supplies root-owned, world-readable files. To
inspect ownership after installation:

```sh
pacman -Qo /usr/local/etc/vimrc/vimrc /etc/profile.d/viminumrc.sh
pacman -Qkk viminumrc
```

## Activation and updates

New login sessions that read `/etc/profile` get the setting for all
users, including root. Arch's Bash and Zsh login shells do this.
Existing shells can activate it immediately after installation with:

```sh
. /etc/profile.d/viminumrc.sh
```

Child processes inherit the export. Shells or services that neither read
the profile nor inherit its environment do not acquire it. Plain
`sudo vim` may discard `VIMINIT`; use a root login session or an
explicit `sudo vim -u /usr/local/etc/vimrc/vimrc` when needed. No sudo
policy is changed by this package.

Vim uses `VIMINIT` before personal vimrc files, so this deliberately
selects the shared configuration instead of `~/.vimrc`. An explicit
`vim -u /path/to/vimrc` overrides it. See Vim's
[startup documentation](https://vimhelp.org/starting.txt.html#VIMINIT).
This package does not configure Neovim.

Edit the versioned sources here to record future changes, update
`sha256sums` with `makepkg -g`, bump `pkgrel`, rebuild, and install the
new archive. The vimrc and profile snippet are listed in `backup`, so
pacman preserves local edits according to its
[configuration backup rules](https://man.archlinux.org/man/pacman.8.en#HANDLING_CONFIG_FILES).
Review any `.pacnew` or `.pacsave` files; an installed version alone
does not prove those configuration files match the package. Bundled
plugin files are package payload and are replaced on upgrade.
