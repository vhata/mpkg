# viminumrc

`viminumrc` is a self-contained Vim configuration for editing files over
SSH and working in system accounts. It provides editing defaults,
keybindings, search, and bundled surround operations. Plugins are
included locally; no plugin manager or runtime downloads are needed.
Directory search uses `rg` when available and falls back to Vim.

Use a normal Vim 8+ installation with its standard runtime, including
netrw. Minimal `vi`/`vim-tiny` builds are not supported. It also works
as a Neovim `init.vim` with the standard runtime.

## Use it

Try it without changing your existing config:

```sh
vim -u /usr/local/etc/vimrc/vimrc /path/to/file
```

Copy **`vimrc` and the entire `bundle/` directory** together. For an
account without an existing Vim configuration, run from this directory:

```sh
mkdir -p "$HOME/.vim"
cp -R ./bundle "$HOME/.vim/"
install -m 600 ./vimrc "$HOME/.vim/vimrc"
```

Vim loads `~/.vim/vimrc` automatically when there is no `~/.vimrc`.
Review or back up an existing configuration first; an older `~/.vimrc`
would take precedence. The top-level README is only a reference. Keep
the bundle's attribution and license files when copying it.

For Neovim, copy `vimrc` as `~/.config/nvim/init.vim` and `bundle/` as
`~/.config/nvim/bundle/`, in an account without an existing Neovim
configuration. To try it directly: `nvim -u /path/to/vimrc`. Bundled
files are located relative to the vimrc, including when the vimrc is a
symlink.

## What you get

- Syntax highlighting, filetype indentation, two-space defaults, and
  visible Markdown syntax. Built-in filetype rules still apply, such as
  literal tabs in Makefiles.
- Absolute and relative line numbers, current-line highlighting, a
  compact status line, and a little space around the cursor.
- Incremental, highlighted search: case-insensitive until the pattern
  contains a capital letter. `n`/`N` center the match and open folds.
- Manual completion from words in open buffers; no automatic popup.
- Add, change and delete surrounding quotes, brackets and tags, with
  normal-mode dot-repeat. The implementation is bundled locally.
- Multiple buffers, splits, netrw browsing, and quickfix search with
  optional ripgrep acceleration and a built-in fallback.
- No auto-save or format-on-save. No automatic text wrapping or comment
  continuation while typing; explicit `gq` and `=` still work.

## Keys

Leader is **Space**. These mappings use normal mode unless noted.

| Key                               | Action                                                                 |
| --------------------------------- | ---------------------------------------------------------------------- |
| `Space w`                         | Save                                                                   |
| `Space qq`                        | Quit all, prompting for unsaved changes                                |
| `Space Space` / `Space ff`        | Start `:edit`; type a path and use Tab completion                      |
| `-` / `Space e`                   | Browse the current file's directory with netrw                         |
| `Space fn`                        | New empty buffer                                                       |
| `H` / `L`                         | Previous / next buffer                                                 |
| ``Space ` ``                      | Alternate buffer                                                       |
| `Space ,` / `Space fb`            | List buffers, then enter a buffer number or name                       |
| `Space bd`                        | Delete the buffer, prompting for unsaved changes                       |
| `Space -` / `Space \|`            | Split below / right                                                    |
| `Ctrl+h/j/k/l`                    | Move between windows                                                   |
| `Space wd`                        | Close window                                                           |
| `Esc`                             | Clear search highlighting                                              |
| `Space sg` / `Space /`            | Start `:Search`; type literal text to find below the current directory |
| `Space xq` / `Space xc`           | Open / close quickfix results                                          |
| `[q` / `]q`                       | Previous / next quickfix result                                        |
| `Space uw`                        | Toggle display wrapping; `j`/`k` follow display lines                  |
| `Space ul` / `Space uL`           | Toggle absolute / relative numbers independently                       |
| `Space us`                        | Toggle spellcheck (uses installed Vim dictionaries)                    |
| `Space uW`                        | Toggle visible whitespace                                              |
| `Space tp`                        | Toggle paste mode for terminals without bracketed paste                |
| `<` / `>` in visual mode          | Indent and keep the selection                                          |
| `]e` / `[e` or `Alt+j` / `Alt+k`  | Move the line or selected lines down / up                              |
| `Space cf`                        | Reindent the file, or the visual selection, preserving the view        |
| `Space ?` / `:VimrcKeys`          | Show a compact keybinding reference inside Vim                         |
| `ys{motion}{delimiter}`           | Surround a motion, e.g. `ysiw"` quotes a word                          |
| `yss{delimiter}`                  | Surround the line's text                                               |
| `cs{old}{new}`                    | Change a surround, e.g. `cs"'` changes double to single quotes         |
| `ds{delimiter}`                   | Delete a surround, e.g. `ds"` removes double quotes                    |
| `S{delimiter}` in visual mode     | Surround the selection                                                 |
| `Ctrl+Space` in insert mode       | Open word completion (`Ctrl+n` also works)                             |
| `Ctrl+n` / `Ctrl+p` in completion | Next / previous suggestion                                             |
| `Tab` / `Ctrl+e` in completion    | Accept / cancel                                                        |

In netrw, Enter opens a file and `-` goes up a directory. It has its own
buffer-local keys; press `F1` for help. It is a browser, not Oil's
editable filesystem view. Outside netrw, `-` replaces Vim's usual
previous-line motion; `H`/`L` replace its top/bottom-of-screen motions.

For surrounds, a closing bracket such as `)` adds a tight pair `(text)`;
an opening bracket such as `(` adds spaces `( text )`. Press Esc to
cancel a pending delimiter. `.` repeats normal-mode surround operations;
visual surrounds are not dot-repeatable. Attribution and exact upstream
revisions are in [`bundle/README.md`](bundle/README.md). Surround's
insert-mode mappings are disabled; use normal or visual mode.

Line movement accepts a count, such as `3]e`, and stops at the first or
last line. In visual mode it moves whole lines and keeps the selection,
including when the selection was characterwise or blockwise. Movement
preserves indentation and registers; use `Space cf` separately to
reindent. The `]e` / `[e` alternatives work when the terminal does not
send Alt keys. Reindent uses Vim's filetype rules, not an external
formatter, and does not run automatically on save.

For search across files, type `Space sg`, enter text and press Enter:

```vim
:cd /etc/nginx
:Search listen
```

Search is recursive under `:pwd`; use `:cd /path` to scope it. Text is
literal (including spaces and punctuation), without enclosing quotes.
Lowercase queries ignore case; queries containing uppercase letters
match case, including accented letters. Vim's internal encoding is set
to UTF-8; file encodings are still detected separately. Results open in
quickfix, with one entry per occurrence. No matches clears the results;
detected errors keep the previous results.

When `rg` is on PATH, search uses its JSON output to preserve filenames
and disables its user configuration. It searches saved files and honors
ignore files, skipping hidden files and binary files by default. Nothing
installs or updates `rg`; its binary is not part of the copyable bundle.
Non-UTF-8 results are reported as errors; use `:vimgrep` for those
files.

Without `rg`, search uses Vim's `vimgrep` over `**/*`. It is slower,
does not honor ignore files, and can search unsaved text in loaded
buffers. It skips hidden paths through the glob but may search binary
files. Vim can report unreadable files as warnings rather than errors,
leaving partial results; this fallback does not guarantee a complete
traversal. Both backends leave your ordinary `/` search pattern
unchanged. Search is synchronous; scope the directory to avoid scanning
a large tree.

For regexes, hidden files, or a particular file glob, use Vim directly:

```vim
:vimgrep /listen\|server_name/j /etc/nginx/*.conf
:copen
```

Use `\c` or `\C` inside a vimgrep pattern to force case-insensitive or
case-sensitive search. This is quickfix search, not a live fuzzy picker.

Other useful built-ins: `Ctrl+x Ctrl+f` completes filenames in insert
mode; `==` reindents a line; `gg=G` reindents a file; `gqap` wraps a
paragraph; `u` / `Ctrl+r` undo / redo; `:earlier 5m` goes back through
undo history in the current session.

## Account-friendly defaults

Modelines and per-directory vimrc loading are disabled. Swap files and
temporary write backups remain enabled for recovery, with
`backupcopy=yes` to preserve symlinks and hard links when writing. There
are no persistent undo files, saved registers/command history, sessions,
or netrw directory history. Swap files still contain edited text.

Mouse capture is off, so ordinary terminal selection works. Clipboard
sharing depends on the terminal/editor build; this file adds no tmux
integration. Save with `Space w` or `:w`; no `Ctrl+s` mapping is needed
on terminals where flow control captures it. There is no LSP, AI, Git
UI, automatic comment toggler, formatter, or external fuzzy finder.
