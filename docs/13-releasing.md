# Releasing

A release is a signed `vX.Y.Z` tag on a merge commit on `main`. The tag run in `.github/workflows/ci.yml` runs the amd64 image, builds and runs an arm64 image natively, publishes both platforms to `ghcr.io/danjonesio/porymcp`, and then pulls the published image and runs it on each platform. Which tags it publishes, which of them move and what each job proves are in `docs/08-docker.md`, Images and tags. This page covers the number, the steps in order, and what to do when a step goes red.

Every release has a release issue, the issue that tracks the cut (PORM-131 for v0.1.0). It records the number and any exception to the rules below, its branch carries the release pull request, and it is closed once the release page exists. Branch names and commit messages follow `CONTRIBUTING.md`, Branches and pull requests.

Cutting a release needs write access to the repository, `gh` signed in, Docker with buildx, nvm, Go, make, and a key git signs tags with. For an SSH key, git needs the key, the format, and a file of allowed signers that `git tag -v` reads:

```
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

For a GPG key, `user.signingkey` is the key id and `git tag -v` reads the GPG keyring.

## The number

Versions follow semantic versioning, `vMAJOR.MINOR.PATCH`. The next number is decided from every `###` heading under `## Unreleased` in `CHANGELOG.md`, and the largest case among them decides:

- Only fixes, with no change to the API, the MCP behaviour, the configuration or the stored data: a patch (`v0.1.0` to `v0.1.1`).
- New behaviour that keeps existing clients, configurations and data working, such as a new route, field, auth type or schema version: a minor (`v0.1.1` to `v0.2.0`).
- An entry whose heading starts `### Breaking:`: a minor while the major is 0, and a major from `v1.0.0` on. `Breaking:` is the marker; an entry that changes a contract carries it.

The rule reads only the headings, so first check that every change since the last tag has one. This lists the pull requests merged since then:

```
git fetch origin --tags
git log --first-parent --merges --format='%as %s' "$(git describe --tags --abbrev=0 origin/main)"..origin/main
```

A change a user or operator can see (a route, a field, the dashboard, the proxy's behaviour, a schema step, a toolchain or base image move) has a `###` heading that names its issue. Dependency bumps that change no behaviour, and changes to CI, tests or docs alone, have none. A missing heading is added in a pull request of its own before the release pull request.

A release candidate is `vX.Y.Z-rc1`, `-rc2` and so on; `docs/08-docker.md` says which tags it publishes. A number is never reused once its tag has been pushed: the Go checksum database records the module at a version the first time anyone fetches it, so a second commit under the same tag fails every later fetch. The release issue records any exception to these rules.

## Before the tag

One pull request, on the release issue's branch, makes the release commit and nothing else. `YYYY-MM-DD` below is the day the pull request is expected to merge, and the tag follows on the same day.

1. Branch from an up-to-date `main`:

   ```
   git switch main && git pull --ff-only origin main
   git switch -c <the release issue's branch name>
   ```

2. Rename `## Unreleased` in `CHANGELOG.md` to `## vX.Y.Z (YYYY-MM-DD)` and add a new, empty `## Unreleased` above it.
3. Set `info.version` in `openapi.yaml` to `X.Y.Z`.
4. Set the dashboard's version with the Node release in `web/.nvmrc`, so the lockfile is written by the npm the project uses. The brackets run it in a subshell, so the shell stays in the repository root; `nvm install` installs that release when it is missing, then uses it:

   ```
   (cd web && nvm install && npm version X.Y.Z --no-git-tag-version)
   ```

   This changes `web/package.json` and both version entries in `web/package-lock.json`. The lockfile is never edited by hand. nvm is a shell function: in a shell that has not loaded it, run `source ~/.nvm/nvm.sh` first.
5. Check the change and run the tests:

   ```
   git diff --stat
   make test
   ```

   `git diff --stat` lists exactly four files: `CHANGELOG.md`, `openapi.yaml`, `web/package.json` and `web/package-lock.json`. `make test` exits 0.
6. Commit the four files, push, open the pull request and wait for its four checks (`go`, `web`, `docker` and `docker-arm64`) to pass:

   ```
   git add CHANGELOG.md openapi.yaml web/package.json web/package-lock.json
   git commit -m "PORM-NN: release vX.Y.Z" -m "Verify: make test"
   git push -u origin HEAD
   gh pr create --base main --title "PORM-NN: release vX.Y.Z" --body "The release commit for vX.Y.Z."
   gh pr checks --watch
   ```

7. Merge it with a merge commit (`gh pr merge --merge`, or Create a merge commit on the pull request page). That merge commit is what gets tagged.

The MCP handshake reports the version `dev` until PORM-59 stamps a build version into the binary from the tag; PORM-59 removes steps 3 and 4 from this page when it lands. The branch name carries the release issue's id, so merging the pull request closes the issue by automation; move it back to In Progress until the release page exists.

## The tag

From an up-to-date `main`, find the release pull request's merge commit and the `main` run for it:

```
git switch main && git pull --ff-only origin main
gh pr view <release pull request number> --json mergeCommit --jq .mergeCommit.oid
gh run list --workflow ci --commit <merge sha> --event push
gh run watch <run id> --exit-status
gh run view <run id> --json jobs --jq '.jobs[] | [.name, .conclusion] | @tsv'
```

Every job of that run reads `success`, with one exception: `deploy` may read `failure`. It redeploys the deployment that follows `edge` and checks nothing about the image, which both `verify` legs have already run, and `ci.yml` does not make it a required check. Any other red job stops the release: fix it on `main` in a pull request of its own, and tag that pull request's merge commit instead once its run passes. The number is not spent until a tag is pushed.

Then sign the tag on the merge commit, check it, and push that one tag by name:

```
git tag -s vX.Y.Z -m "PoryMCP vX.Y.Z" <merge sha>
git tag -v vX.Y.Z
git push origin refs/tags/vX.Y.Z
```

`-s` signs the tag whatever `tag.gpgsign` says; `-a` alone makes an unsigned tag when that setting is off. `git tag -v` checks the signature before anything leaves the machine. It prints the tag, whose `object` line is the merge sha, and `Good "git" signature` for an SSH key or `Good signature` for a GPG key. If it fails, stop before the push: fix the key setup at the top of this page, delete the local tag with `git tag -d vX.Y.Z`, and sign it again. Never re-tag without `-s`. The push prints `* [new tag] vX.Y.Z -> vX.Y.Z`, and from then on the number is spent.

The push names one ref. `--tags` pushes every local tag, `--follow-tags` every annotated tag reachable from the pushed commits, `--all` every branch, and `--mirror` also deletes remote refs that do not exist locally; none of them is used for a release.

## The run and the digest

The tag push starts one run of the `ci` workflow on the tag. It can take a minute to be listed; repeat the first command until it is:

```
gh run list --workflow ci --event push --branch vX.Y.Z
gh run watch <run id> --exit-status
```

A non-zero exit from the watch goes to When it goes red. When it is green, read the published digest from the registry and from the run, and check that every reading is the same digest:

```
docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:vX.Y.Z --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:latest --format '{{.Manifest.Digest}}'
gh run view <run id> --json jobs --jq '.jobs[] | [.name, .databaseId] | @tsv'
gh run view <run id> --log --job <publish job id> | grep -A1 'group.Digest'
gh run view <run id> --log --job <verify job id> | grep 'image ghcr.io/'
```

The third command lists the run's jobs with their ids. The fourth prints a `##[group]Digest` line with the digest the build step pushed on the line under it. The fifth prints `image ghcr.io/danjonesio/porymcp@sha256:...`, the reference a `verify` leg ran; run it once for `verify (amd64)` and once for `verify (arm64)`. The run's summary page (`gh run view <run id> --web`) shows the same digest on its `Published` line. For a release candidate, skip the `latest` reading. `edge` at the same commit carries its own digest, because the push to `main` built it in a separate run. Readings that differ mean a tag points at an image this run did not check: announce nothing, and treat it as a bad image (When it goes red).

## Proving the image

The tag run proves the image on both platforms without a person in the loop: `publish` waits for `docker` and `docker-arm64`, and `verify (amd64)` and `verify (arm64)` run the published image after it. What each of those jobs proves, and what it does not, is in `docs/08-docker.md`, Images and tags. Read the jobs' results:

```
gh run view <run id> --json jobs --jq '.jobs[] | [.name, .conclusion] | @tsv'
```

It prints eight rows. `go`, `web`, `docker`, `docker-arm64`, `publish`, `verify (amd64)` and `verify (arm64)` read `success`, and `deploy` reads `skipped`: only a run from `main` deploys. A missing row fails the check as a red one does.

The checks are `scripts/image-check.sh`, and repeating one by hand is optional. To repeat it against the published image on a host of either architecture, check out the tag (`git switch --detach vX.Y.Z`), `docker pull` the reference `ghcr.io/danjonesio/porymcp@sha256:<digest>`, and follow `make image-check` in `CONTRIBUTING.md` with `IMAGE_CHECK_REF` set to that reference. Afterwards `docker rm -f porymcp-ci` and `docker rmi` the image.

## After

The release page is created from the tag with notes written by hand into a file outside the repository, which is deleted afterwards:

```
notes="$(mktemp)"
gh release create vX.Y.Z --verify-tag --title 'PoryMCP vX.Y.Z' --notes-file "$notes"
rm "$notes"
```

Between the first two commands, write the notes into `$notes`, from the tracked `CHANGELOG.md` only, in this order:

1. An `Upgrading` paragraph that copies every sentence under the release's heading asking an operator to act before or after the upgrade: a backup, a one-way schema step and its rollback, a new or changed variable, and each `Breaking:` entry in full. With none, it reads `Nothing to do before upgrading.`
2. One line per `###` heading under the release's heading.
3. The image and its digest, `ghcr.io/danjonesio/porymcp@sha256:<digest>`, and the pull line, `docker pull ghcr.io/danjonesio/porymcp:vX.Y.Z`.

`--generate-notes` is not used: it publishes the title of every pull request merged since the last release, text that no check in this repository reads.

A README sentence that speaks of this release as still to come comes out in a one-line pull request; most releases have none. Then close the release issue.

## When it goes red

- A check fails on the tag run (`go`, `web`, `docker` or `docker-arm64`). `publish` did not run and nothing was published. `web-audit` reads a live advisory database, so the `web` job can fail on a commit that was green an hour earlier. Do not re-dispatch the tag. Fix the cause or bump the dependency on `main`, and make that pull request the next patch's release commit as well: it renames the changelog heading to the next patch number and sets `openapi.yaml` and `web/package.json` to it, as in Before the tag. Then cut the next patch. The pushed tag stays where it is, with no image and no release page. A job that failed because its runner was lost or the job was cancelled, not because a step failed, may be re-run once with `gh run rerun <run id> --failed`; its annotation says the runner lost communication or the job was cancelled, where a failed check names its step.
- `publish` fails after every check passed, before the release page is created. Re-dispatch the tag once, and only if no image tag was pushed: the `publish` log has no `Digest` group (the fourth command in The run and the digest prints nothing) and `docker buildx imagetools inspect ghcr.io/danjonesio/porymcp:vX.Y.Z` reports that the tag is not found.

  ```
  gh workflow run ci --ref vX.Y.Z
  gh run list --workflow ci --event workflow_dispatch --branch vX.Y.Z
  ```

  The dispatched run's event is `workflow_dispatch`, so the second command finds it where the `--event push` list does not; continue from The run and the digest with its id. If an image tag was pushed, or the dispatched run fails too, cut the next patch instead. A dispatch from `main` republishes `edge` and redeploys the deployment that follows it, so `--ref main` is never part of a release.
- The image is bad after the tag, including a red `verify` or digest readings that differ. Cut the next patch; `latest` keeps pointing at the bad digest until that run publishes. Deleting a package version breaks every pull that does not pin a digest, so the next patch is preferred. A deletion is a deliberate act and needs a wider token for its length only: the first command widens it, the second and third find and delete the version, and the last narrows the token straight after.

  ```
  gh auth refresh -h github.com -s read:packages,write:packages,delete:packages
  gh api /user/packages/container/porymcp/versions --jq '.[] | [.id, .name, (.metadata.container.tags | join(","))] | @tsv'
  gh api -X DELETE /user/packages/container/porymcp/versions/<version id>
  gh auth refresh -h github.com -r delete:packages,write:packages
  ```

- A tag is wrong. Before the push, delete it with `git tag -d vX.Y.Z` and make it again; `git tag -s` refuses a name that already exists. After the push, a tag on the wrong commit spends its number: cut the next patch.
