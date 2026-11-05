# Install and maintain RepoScan

These instructions apply to **RepoScan 0.3.1**. Install from the trusted
release checkout or source archive. The package has not been published to
PyPI.

| Name | Purpose |
| --- | --- |
| `threatprophet-reposcan` | Python distribution name, used by installation and removal tools |
| `reposcan` | Command to run a scan |
| `reposcan` | Python import package |

The bare `reposcan` package on PyPI belongs to an unrelated project. The local
path in `pipx install '.[yara]'` selects this checkout explicitly.

## Requirements and scope

RepoScan supports Linux with Python 3.10 or later. Native Windows is
unsupported; macOS needs native verification. An installation tool's support
for other platforms does not establish RepoScan support.

The convenience and manual installation paths need working Python `venv`
support, including the ability to create an environment with pip.

Install the scanner from its trusted checkout, separate from the unfamiliar
project you want to inspect. The `[yara]` extra supplies `yara-python` for
canonical scanning. A separate YARA CLI is useful for that engine choice and
contributor verification, but is not needed for the Python engine.

Installation can download dependencies and run their build steps. The scan
itself reads the selected target as data. Supply the unfamiliar project only
as the target argument to `reposcan`.

## Obtain the release

With Git installed, clone the tagged version and enter its directory:

```bash
git clone --branch v0.3.1 --depth 1 https://github.com/ThreatProphet/RepoScan.git
cd RepoScan
```

Alternatively, download the source archive from the
[v0.3.1 release](https://github.com/ThreatProphet/RepoScan/releases/tag/v0.3.1),
extract it, and open a terminal in the extracted directory containing
`pyproject.toml` and `install.sh`.

Choose one installation method below from that trusted directory.

## Install with pipx

[Install pipx](https://pipx.pypa.io/latest/how-to/install-pipx.html) using its
instructions for your operating system. Pipx has its own Python requirements;
follow those as well as RepoScan's requirements. Ensure its application
directory is on your `PATH`.

From the trusted RepoScan checkout:

```bash
pipx install '.[yara]'
pipx list
reposcan --version
reposcan /absolute/path/to/received-project
```

Pipx installs the application in a separate environment and exposes the
`reposcan` command. The expected distribution name in `pipx list` is
`threatprophet-reposcan`.

If the shell cannot find `reposcan`, follow the PATH instructions from pipx
and open a new terminal when needed. If another `reposcan` command already
exists, identify its owner before replacing anything. See
[migration from an earlier preview](#migrate-from-an-earlier-preview).

## Install with the convenience script

For setup without pipx, run the script from the trusted scanner checkout:

```bash
bash ./install.sh
```

The installer uses an existing Python interpreter. It creates a dedicated
virtual environment, installs this checkout with YARA support, and verifies
that the installed package comes from that environment. It then runs a benign
scan with `yara-python`, which loads and compiles the packaged rules. The
command is exposed only after those checks succeed.

Defaults:

- Environment: `$XDG_DATA_HOME/threatprophet-reposcan` when `XDG_DATA_HOME`
  is an absolute, nonempty path; otherwise
  `$HOME/.local/share/threatprophet-reposcan`.
- Command: `$HOME/.local/bin/reposcan`.
- Interpreter: `python3`.

Explicit paths and interpreter selection are available:

```bash
bash ./install.sh \
  --prefix "$HOME/.local/share/threatprophet-reposcan-custom" \
  --bin-dir "$HOME/.local/bin" \
  --python python3
```

Use `bash ./install.sh --help` for the interface. The script does not edit shell
profiles. Use the command path it prints if the selected bin directory is not
on your `PATH`.

The installer refuses an existing installation prefix, destination command,
or another `reposcan` command already on `PATH`. Choose one installation method
and resolve an existing installation before switching methods. A failed
installation leaves any newly created environment for inspection, with no new
command exposed. After resolving the failure, remove only the reported partial
environment or choose a new prefix.

## Install in a manual virtual environment

Use a fresh environment directory. If `.venv` already exists, choose a new
name and adjust the following paths:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install '.[yara]'
source .venv/bin/activate
reposcan --version
reposcan /absolute/path/to/received-project
```

Activation makes the README's `reposcan` commands available in that shell.
Without activation, use `.venv/bin/reposcan` explicitly.

## Check the installation

`reposcan --version` checks that the command starts. A scan also checks engine
readiness. From the trusted checkout, the inert example is:

```bash
reposcan tests/fixtures/web3market-entry --engine yara-python --color never
```

The expected result is `review-needed`, three findings across two files, and
exit code `1`. The fixture files are scanned as data. Read the
[case study](web3market.md) for the exact findings and limitations.

The [contributor installation checks](../CONTRIBUTING.md#verify-changes)
exercise a built wheel outside the source checkout, including benign and inert
positive inputs. A missing engine is an installation problem, not a clean
scan result. Keep `[yara]` in the install command unless you deliberately
provide the YARA CLI yourself. Explicit `--engine lite` selects a different,
heuristic mode with its own findings.

## Update and remove

Review the new scanner version before installing it. For a pipx installation,
run the following from the updated trusted checkout:

```bash
pipx uninstall threatprophet-reposcan
pipx install '.[yara]'
reposcan --version
```

To remove the pipx installation without reinstalling:

```bash
pipx uninstall threatprophet-reposcan
```

The convenience installer prints removal commands for its own command link and
environment. Use those paths when removing that installation, then run the
installer from the updated trusted checkout. It intentionally refuses to
overwrite an existing environment. For a manual virtual environment, leave
the environment if it is active and remove only the environment directory you
created for RepoScan.

Keep scan reports outside the installation directory so they remain separate
from installation and removal.

## Migrate from an earlier preview

Earlier previews used `reposcan` as both the distribution and command name.
Version 0.2.0 changes the distribution to `threatprophet-reposcan` while
retaining the command and Python import.

Inspect an existing pipx installation with `pipx list --json` to identify its
recorded source. Remove an old ThreatProphet preview under its recorded
distribution name before installing this version. The name `reposcan` alone
does not identify which project installed it.

For a manual environment, create a fresh one. Installing both distribution
names into the same environment can leave overlapping ownership of the
`reposcan` module and executable. A fresh environment avoids that ambiguity.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `reposcan` is not found | Use the command path reported by the installer or configure the installation tool's bin directory on `PATH`. |
| A command or environment already exists | Identify the existing installation and use its removal method. The convenience installer does not overwrite it. |
| Default scan exits `69` | Check that YARA support was installed in the scanner's environment, or that an intentionally selected YARA CLI is available. |
| `yara-python` fails to install | Review the package-manager error and the upstream [yara-python installation guidance](https://github.com/VirusTotal/yara-python#installation). Native build requirements can depend on the interpreter and available wheels. |
| A scan returns `1` or `2` | Read the findings. These are review results, not installer failure codes. |

Include the RepoScan version, installation method, platform, engine, and
sanitized error when [reporting an installation problem](https://github.com/ThreatProphet/RepoScan/issues/new?template=bug_report.yml).
