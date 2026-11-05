# Prepare and publish a release

Release preparation is a separate commit from the changes being released.
Merge the version and documentation updates before creating the public tag.
Pushing a tag does not update package metadata.

The [release workflow](../.github/workflows/release.yml) runs CI, validates the
tag against the source, builds distributions, verifies the exact wheel,
generates checksums, and creates a **draft GitHub release**. Publishing that
draft is the final maintainer step. The workflow does not publish to PyPI.

## 1. Prepare the version in a pull request

Start from current `origin/main` on a release-preparation branch. For this
release, use `0.3.1` and the tag `v0.3.1`.

Update these together:

- `pyproject.toml`: the distribution version.
- `src/reposcan/__init__.py`: the literal runtime `__version__`.
- `CHANGELOG.md`: one nonempty `## VERSION - YYYY-MM-DD` section using the
  release date. Its contents become the generated draft's release notes.
- README and installation instructions: current version, clone tag, and
  download links.
- Contributor commands: versioned wheel filenames.
- Example reports: regenerate them with the candidate scanner.
- Recording source and guide: exact version assertions and release labels.
  Existing recordings may remain if their original version is described
  accurately; regenerate them when changing their displayed release branding.

Preserve historical changelog entries and migration notes. Changing the tool
version does not itself require changing the JSON schema version.

Follow [the contributor checks](../CONTRIBUTING.md#verify-changes), merge the
preparation pull request, and wait for CI on its merged commit to pass. The
current CI matrix covers Linux with Python 3.10 and 3.12. The release packaging
job uses Python 3.12; this does not change the scanner's Python 3.10+ requirement.

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
  release_version=0.3.1
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
and select the run for the new tag. Wait for the verification, packaging, and
draft jobs to succeed. A successful ordinary branch CI run does not replace
the tag's release validation.

Then open [Releases](https://github.com/ThreatProphet/RepoScan/releases) while
signed in with maintainer access. The draft must contain the notes extracted
from the tagged changelog and these three uploaded assets, with the chosen
version in both distribution filenames:

- `threatprophet_reposcan-0.3.1-py3-none-any.whl`
- `threatprophet_reposcan-0.3.1.tar.gz`
- `SHA256SUMS`

GitHub's automatic source-code ZIP and tar archives are separate from the
built source distribution and wheel.

The workflow checks the exact wheel outside the source checkout, exercises a
fresh pipx installation with native YARA, verifies uninstall, and hashes the
uploaded distributions. Keep those assets with the tag that produced them.

Review the draft title, notes, version, and assets, then publish it as the
latest regular release. Confirm the published download links and README
installation tag resolve.

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
