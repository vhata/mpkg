# Guest Python build

`guest-python-build.sh` builds the fixture's pinned Python 3.12.16 source
after the installed disposable guest and reviewed source transfer are
ready. Invoke it through the runner's verified console transport. It
requires the matching QEMU UUID, six-field root-owned marker, actual
`vda2` root filesystem, disk serial and 40 GiB disk size before mutation.

The source must be root-owned at
`/opt/mpkg-proof-inputs/sources/python/Python-3.12.16.tar.xz`; its frozen
SHA-256 is checked before and after copying to the private builder area.
The script refuses existing build state, users, units and installation
prefixes. It does not install packages, fetch sources or contact Docker.

The launcher installs a protected fixed worker and starts
`mpkg-fixture-python-build.service`, then immediately returns the console.
The manager owns the job independently of the initiating connection.
The unit has a 3,600-second limit, no restart and control-group shutdown.
Only one build should run inside the TCG guest at a time.

The dedicated `mpkg-pybuild` account extracts, configures, compiles and
installs into a staging directory without root privileges. Configuration
uses `/opt/mpkg-python/3.12.16` and disables ensurepip. The administrator
publishes the result only after the builder exits, no builder process
survives, and the bounded staged tree passes type, mode and link checks.
The worker checks the exact interpreter version and required modules,
then records the installed tree hash and linked libraries.

Private results remain under `/var/lib/mpkg-fixture/python-3.12.16/`:

- `build.log` and `commands.txt` retain compilation evidence.
- `builder.txt` and `compiler.txt` bind the build account and compiler.
- `result.json` binds source, interpreter, modules and installed tree.
- `linked-libraries.txt` records the executable and extension libraries.
- `started`, numeric `exit`, and `complete` distinguish progress and
  successful completion. The service manager's result must also be checked.

A timeout or interrupted publication preserves its state. Missing exit
or completion evidence is not success and does not authorize another
launch over that state. Restore a separately verified disposable snapshot
before a fresh attempt; retain failed evidence first.

The host-safe tests exercise wrong-host refusal and staged-tree boundary
cases. They execute no build, installation, service or guest operation.
Only an actual guest run can establish interpreter build success.
