# Releasing

A release is a signed `vX.Y.Z` tag on a merge commit on `main`. The tag run in `.github/workflows/ci.yml` runs the amd64 image, builds and runs an arm64 image natively, publishes both platforms to `ghcr.io/danjonesio/porymcp`, and then pulls the published image and runs it on each platform. Which tags it publishes, which of them move and what each job proves are in `docs/08-docker.md`, Images and tags. This page covers the number, the steps in order, and what to do when a step goes red.

## The number

Versions follow semantic versioning, `vMAJOR.MINOR.PATCH`. The next number is decided from what sits under `## Unreleased` in `CHANGELOG.md`:

- Only fixes, with no change to the API, the MCP behaviour, the configuration or the stored data: a patch (`v0.1.0` to `v0.1.1`).
- New behaviour that keeps existing clients, configurations and data working: a minor (`v0.1.1` to `v0.2.0`).
- An entry whose heading starts `### Breaking:`: a minor while the major is 0, and a major from `v1.0.0` on. `Breaking:` is the marker; an entry that changes a contract carries it.

A release candidate is `vX.Y.Z-rc1`, `-rc2` and so on; `docs/08-docker.md` says which tags it publishes. A number is never reused once its tag has been pushed: the Go checksum database records the module at a version the first time anyone fetches it, so a second commit under the same tag fails every later fetch. The release issue records any exception to these rules.

## Before the tag

One pull request, on the release issue's branch, makes the release commit and nothing else:

1. Rename `## Unreleased` in `CHANGELOG.md` to `## vX.Y.Z (YYYY-MM-DD)` and add a new, empty `## Unreleased` above it.
2. Set `info.version` in `openapi.yaml` to `X.Y.Z`.
3. Set the dashboard's version with the Node release in `web/.nvmrc`, so the lockfile is written by the npm the project uses:

   ```
   cd web && nvm use && npm version X.Y.Z --no-git-tag-version
   ```

   This changes `web/package.json` and both version entries in `web/package-lock.json`. The lockfile is never edited by hand.
4. Check the change and run the tests:

   ```
   git diff --stat
   make test
   ```

   `git diff --stat` lists exactly four files: `CHANGELOG.md`, `openapi.yaml`, `web/package.json` and `web/package-lock.json`.

The MCP handshake reports the version `dev` until PORM-59 stamps a build version into the binary from the tag; that issue also retires steps 2 and 3. If the branch name carries the release issue's id, merging the pull request closes the issue by automation; move it back until the image is proved.

## The tag

From an up-to-date `main` whose last run is green, sign the tag on the merge commit of the release pull request and push that one tag by name:

```
git switch main && git pull --ff-only origin main
gh run list --workflow ci --branch main --event push --limit 1
git tag -s vX.Y.Z -m "PoryMCP vX.Y.Z" <merge sha>
git tag -v vX.Y.Z
git push origin refs/tags/vX.Y.Z
```

`-s` signs the tag whatever `tag.gpgsign` says; `-a` alone makes an unsigned tag when that setting is off. `git tag -v` checks the signature before anything leaves the machine. For an SSH signing key it needs the signer in the file `gpg.ssh.allowedSignersFile` names; if it fails, stop before the push and fix the verification, and never re-tag without `-s`.

The push names one ref. `--tags` pushes every local tag, `--follow-tags` every annotated tag reachable from the pushed commits, `--all` every branch, and `--mirror` also deletes remote refs that do not exist locally; none of them is used for a release.

## The run and the digest

The tag push starts one run of the `ci` workflow on the tag:

```
gh run list --workflow ci --event push --branch vX.Y.Z
gh run watch <run id> --exit-status
```

When it is green, read the published digest from the registry and from the run, and check that every reading is the same digest:

```
docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:vX.Y.Z --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:latest --format '{{.Manifest.Digest}}'
gh run view <run id> --json jobs --jq '.jobs[] | [.name, .databaseId] | @tsv'
gh run view <run id> --log --job <publish job id> | grep -A1 'group.Digest'
gh run view <run id> --log --job <verify job id> | grep 'image ghcr.io/'
```

The third command lists the run's jobs with their ids. The fourth prints the digest the build step pushed, and the fifth the reference each `verify` leg ran; run it once for `verify (amd64)` and once for `verify (arm64)`. The run's summary page shows the same digest on its `Published` line. For a release candidate, skip the `latest` reading. `edge` at the same commit carries its own digest, because the push to `main` built it in a separate run.

## Proving the image

The tag run proves the image on both platforms without a person in the loop: `publish` waits for `docker` and `docker-arm64`, and `verify (amd64)` and `verify (arm64)` run the published image after it. What each of those jobs proves, and what it does not, is in `docs/08-docker.md`, Images and tags. Read the jobs' results:

```
gh run view <run id> --json jobs --jq '.jobs[] | [.name, .conclusion] | @tsv'
```

Every row reads `success`. The checks are `scripts/image-check.sh`; to repeat one by hand against the published image on a host of either architecture, follow `make image-check` in `CONTRIBUTING.md` with `IMAGE_CHECK_REF=ghcr.io/danjonesio/porymcp@sha256:<digest>` after a `docker pull` of that reference, then `docker rm -f porymcp-ci` and `docker rmi` the image.

## After

Any README sentence that hedged about the release comes out in a one-line pull request.

The release page is created from the tag with notes written by hand:

```
gh release create vX.Y.Z --verify-tag --title 'PoryMCP vX.Y.Z' --notes-file <file>
```

The notes file holds one line per `###` heading under the release's heading in `CHANGELOG.md`, the image and its digest, and the pull line (`docker pull ghcr.io/danjonesio/porymcp:vX.Y.Z`). It is written from the tracked changelog only, kept outside the repository and deleted afterwards. `--generate-notes` is not used: it publishes the title of every pull request merged since the last release, text that no check in this repository reads.

## When it goes red

- A check fails on the tag run (`go`, `web`, `docker` or `docker-arm64`). `publish` did not run and nothing was published. `web-audit` reads a live advisory database, so the `web` job can fail on a commit that was green an hour earlier. Do not re-dispatch the tag. Fix the cause or bump the dependency on `main`, rename the changelog heading to the next patch number in that pull request, and cut the next patch. A job that failed because its runner was lost or cancelled, not because a check failed, may be re-run once with "Re-run failed jobs".
- `publish` fails after every check passed, before the release is announced. Re-dispatch the tag once, and only if nothing was pushed: the `publish` log has no `Digest` group (the fourth command in The run and the digest prints nothing) and `docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:vX.Y.Z` reports that the tag is not found.

  ```
  gh workflow run ci --ref vX.Y.Z
  ```

  If any tag was pushed, cut the next patch instead. A dispatch from `main` republishes `edge`, so `--ref main` is never part of a release.
- The image is bad after the tag, including a red `verify`. Cut the next patch; `latest` keeps pointing at the bad digest until that run publishes. Deleting a package version is a deliberate act and needs a wider token for the length of the deletion only:

  ```
  gh auth refresh -h github.com -s read:packages,write:packages,delete:packages
  gh auth refresh -h github.com -r delete:packages,write:packages
  ```

  The first command before the deletion, the second straight after it. Deleting the version `latest` points at breaks every pull that does not pin a digest, so the next patch is preferred.
