# `patchtrace build-env`

Reads the build environment of the older and newer file: compiler and linker hints, packer notes and other facts recorded in the PE. It only reads. It does not run either target.

```
patchtrace build-env show ...      # facts read from one or both files
patchtrace build-env delta ...     # what changed between the older and the newer build environment
patchtrace build-env timeline ...  # toolchain change per adjacent build of a series
```

Build facts can help explain some differences, such as a changed compiler or linker signature. They do not prove why a particular function changed, and an identical header does not prove identical code.

A detector's identification (for example Detect It Easy) is a tool observation with its own limits. Run it only through the tool verbs that name it. See [intel-tools](62-cli-intel-tools.md).

Desktop equivalent: the [Build environment panel](27-build-environment-panel.md).

Sources: `src/patchtrace/buildenv/cli.py`, `src/patchtrace/cli_commands/build_env.py`, top-level `patchtrace --help`.
