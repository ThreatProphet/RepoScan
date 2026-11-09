# Prepare and publish a release

Release preparation is a separate commit from the changes being released.
Merge the version and documentation updates before creating the public tag.
Pushing a tag does not update package metadata.

The [release workflow](../.github/workflows/release.yml) runs CI, validates the
tag against the source, builds distributions, verifies the exact wheel,
generates a launcher bound to that wheel, qualifies the exact launcher/wheel
on Linux and both Mac architectures, generates checksums, and creates a
**draft GitHub release**. Publishing that
draft is the final maintainer step. The workflow does not publish to PyPI.

## 1. Prepare the version in a pull request

Start from current `origin/main` on a release-preparation branch and select a
new, unpublished version. The examples below retain the current `0.3.1`
artifact names; replace them with that chosen version. **v0.3.1 is already
published and must not be recreated or reused for these new changes.**

Update these together:

- `pyproject.toml`: the distribution version.
- `src/reposcan/__init__.py`: the literal runtime `__version__`.
- `CHANGELOG.md`: one nonempty `## VERSION - YYYY-MM-DD` section using the
  release date. Its contents become the generated draft's release notes.
- README and installation instructions: current version, clone tag, and
  download links.
- Contributor commands: versioned wheel filenames.
- Quick-run documentation: runtime/platform scope and whether native
  qualification has actually passed. Source launcher pins are refreshed only
  after the new release wheel is publicly available; the release asset itself
  is generated from the exact wheel during packaging.
- Example reports: regenerate them with the candidate scanner.
- Recording source and guide: exact version assertions and release labels.
  Existing recordings may remain if their original version is described
  accurately; regenerate them when changing their displayed release branding.

Preserve historical changelog entries and migration notes. Changing the tool
version does not itself require changing the JSON schema version.

Follow [the contributor checks](../CONTRIBUTING.md#verify-changes), merge the
preparation pull request, and wait for CI on its merged commit to pass. The
CI matrix covers Linux with Python 3.10 and 3.12 plus macOS 15 Apple Silicon and
Intel with Python 3.12. The release packaging job uses Python 3.12; this does
not change the scanner's Python 3.10+ requirement. The quick-run launcher
selects its own pinned CPython 3.12 build.

## 2. Validate the local tag before pushing

Run the following in Bash from a clean trusted checkout after the preparation
commit is merged and its CI succeeds. Use Python 3.11 or later for
`tools/prepare_release.py`, which imports the standard-library `tomllib`.

The subshell stops at the first error. It requires local `main` to match
`origin/main`, creates a local annotated tag, and validates that exact tag
before pushing it. An existing tag is an error; there is no force option.

```bash
(
  set -eu
  release_version=REPLACE_WITH_NEW_VERSION
  release_tag="v$release_version"

  test -z "$(git status --porcelain)"
  git fetch origin --tags
  git switch main
  git merge --ff-only origin/main
  test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"

  git tag -a "$release_tag" -m "RepoScan $release_tag"
  release_check_dir="$(mktemp -d)"
  trap 'rm -rf "$release_check_dir"' EXIT
  python tools/prepare_release.py "$release_tag" \
    --output-directory "$release_check_dir"

  git push origin "refs/tags/$release_tag"
)
```

The preparation helper requires matching tag, distribution, and runtime
versions; a dated nonempty changelog entry; the tag to identify `HEAD`; and the
tagged commit to be reachable from `origin/main`.

If local validation fails, fix the preparation before publishing a tag. A
corrected commit needs a tag that identifies that commit. A local tag that has
never been pushed can be removed and recreated after the correction. Preserve
tags that have already been published.

## 3. Review the automated draft

Open [Prepare release workflow runs](https://github.com/ThreatProphet/RepoScan/actions/workflows/release.yml)
and select the run for the new tag. Wait for verification, packaging, all
three native launcher qualification jobs, and the draft job to succeed.
A successful ordinary branch CI run does not replace
the tag's release validation.

Then open [Releases](https://github.com/ThreatProphet/RepoScan/releases) while
signed in with maintainer access. The draft must contain the notes extracted
from the tagged changelog and these four uploaded assets, with the chosen
version in both distribution filenames:

- `threatprophet_reposcan-0.3.1-py3-none-any.whl`
- `threatprophet_reposcan-0.3.1.tar.gz`
- `reposcan-run.sh`
- `SHA256SUMS`

GitHub's automatic source-code ZIP and tar archives are separate from the
built source distribution and wheel.

The workflow checks the exact wheel outside the source checkout, exercises a
fresh pipx installation with native YARA, verifies uninstall, and hashes both
distributions and the generated launcher. `tools/prepare_launcher.py` writes
the release's wheel version and SHA-256 into that launcher. Native Linux,
Apple Silicon and Intel jobs then download the uploaded artifacts and run
`tools/verify_launcher.py` against the same wheel bytes. The unpublished wheel
is seeded into the launcher's ordinary checksum-verified cache; uv, managed
Python and YARA still start from empty private state. A failed native job
blocks creation of the draft. Keep these assets with the tag that produced them.

Review the draft title, notes, version, and assets, then publish it as the
latest regular release. Confirm the published download links and README
installation tag resolve.

### Refresh the source launcher after publication

The checked-in source launcher intentionally targets a wheel that already
exists. The generated release launcher always targets its own release, so it
does not depend on the source pin being updated first. After publishing the
new release, download its wheel and `SHA256SUMS` into a trusted directory,
verify the wheel checksum, and update the source launcher in a small follow-up:

```bash
python tools/prepare_launcher.py /absolute/path/to/verified-release-wheel.whl \
  --output reposcan-run.sh
python tools/verify_launcher.py
```

Use the actual unchanged release wheel filename in the first command. Update
the README and installation guide's source-launcher version at the same time.
The download verification must use the public wheel, not a fresh local build
with the same version but different bytes. Runtime pins (uv, CPython build,
YARA and platform checksums) are reviewed separately when they change. Test
their native installation before publication.

## Recover from a failed tag

Read the failing job before retrying. Rerunning a tag workflow uses the same
tagged source; editing `main` does not repair an older tag's package metadata.

For a source or version error, prepare and merge a corrective release using a
new version, then validate and push its tag. Explain the correction in its
changelog entry. Do not attach artifacts built from a different commit to an
older tag or disable the validation gates to make it pass.

For this release, `v0.3.0` pointed to source that still declared version 0.2.0.
Its release preparation failed before producing release assets. The corrective
release is `v0.3.1`; the original tag is retained.

A transient infrastructure failure can be retried for the same tag when its
source and metadata are already correct. If a draft already exists, inspect it
before retrying the draft-creation job.
