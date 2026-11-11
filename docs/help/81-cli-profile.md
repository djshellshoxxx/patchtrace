# `patchtrace profile`

Manages analysis profiles without the desktop. A profile is a small JSON file of shared, non-secret analysis settings: detector weights, enabled detectors, symbol policy, CVE providers and cache options. `rank`, `flags` and `correlate` use one with `--profile NAME|FILE`.

```
patchtrace profile list                      # the built-in default and every stored profile
patchtrace profile show NAME|FILE            # one profile and its digest
patchtrace profile validate FILE             # check a file without storing it
patchtrace profile save FILE [--name NAME] [--force]
patchtrace profile delete NAME --confirm
```

Every subcommand takes `--profiles-dir DIR` and `--json`. Without `--profiles-dir` the commands use the per-user profile folder: `%APPDATA%\PatchTrace\profiles` on Windows, `~/.config/PatchTrace/profiles` on Linux.

## Worked example

Write the settings that differ from the default into a file. Fields you leave out keep their default value.

```json
{
  "contract": "profile/1",
  "name": "triage",
  "symbol_policy": "local",
  "snapshot_max_age_days": 7
}
```

Check it, store it and list what is stored. The example keeps its profiles in a folder named `profiles`; leave `--profiles-dir` out to use the per-user folder.

```text
> patchtrace profile validate triage.json --profiles-dir profiles
valid profile triage (digest c9afa976587f6a7bb22bfd9d1aea986b999bd208ec9f3035e8616c8ed9190b9e)

> patchtrace profile save triage.json --profiles-dir profiles
saved profile triage to profiles/triage.json

> patchtrace profile list --profiles-dir profiles
default  7305cb3186271c622d8f73ad2a1f4691f7135367ed45b57f01a9e21a026d47c8  (built-in)
triage  c9afa976587f6a7bb22bfd9d1aea986b999bd208ec9f3035e8616c8ed9190b9e
```

`show` prints the complete profile as it is stored, followed by `digest: ...`. The digest identifies the analysis settings. Two profiles with the same digest rank the same way; the name, the cache folder and the cache budget are not part of it.

Saving a second profile with a stored name is refused until you pass `--force`:

```text
> patchtrace profile save triage.json --profiles-dir profiles
error: a profile named 'triage' already exists; pass --force to replace it
```

Names are compared without regard to case when you save, because two names that differ only in case are the same file on Windows. `--name NAME` stores the file under another name.

Deleting needs `--confirm`. Without it nothing changes:

```text
> patchtrace profile delete triage --profiles-dir profiles
error: nothing was deleted: this removes the stored profile 'triage' from profiles; pass --confirm to do it

> patchtrace profile delete triage --confirm --profiles-dir profiles
deleted profile triage
```

## What is refused

- A file with an unknown field, a value of the wrong type, an unknown detector or more than 64 KiB. The message names the field, for example `error: invalid profile: weights: Input should be a valid dictionary`.
- The name `default`. The built-in default profile cannot be replaced or deleted.
- A name with a path separator or a name Windows reserves, such as `con`.

A profile has no field for an API key or a password. Keys stay session-only.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. |
| 2 | Wrong arguments, a refused file or name, an unknown profile, or `delete` without `--confirm`. |
| 3 | The profile folder cannot be written. For `list`: a stored file is invalid. The valid profiles are still listed and each invalid file is named in a warning. |
| 4 | `delete`: no stored profile has that name. |

`list`, `show` and `validate` write nothing. No subcommand contacts the network, starts a program or asks a question.

Desktop equivalent: **Setup**, **Profiles** tab. The desktop and the commands read the same folder unless the desktop keeps its settings in a file of its own; then pass that folder with `--profiles-dir`. The profile selected in the desktop is not changed by these commands.

Sources: `src/patchtrace/enrichment/profile_cli.py`, `src/patchtrace/enrichment/profiles.py`, `src/patchtrace/cli_commands/profile.py`, `docs/specs/cli-profile-doctor-runtime.md` section 2.
