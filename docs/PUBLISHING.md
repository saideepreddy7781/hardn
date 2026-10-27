# Publishing hardn

Everything is automated by `.github/workflows/release.yml`: pushing a tag like `v0.1.0` runs the tests on
Linux/macOS/Windows, publishes to PyPI, and creates a GitHub Release with standalone binaries,
`hardn.pyz`, and `SHA256SUMS`. You only do the one-time setup below.

> The repo URLs assume `github.com/saideepreddy7781/hardn`. Using another owner or name?
> `grep -rl saideepreddy7781 . --exclude-dir=.git` and replace it in those files first.

## 1. Put it on GitHub (one time)

```bash
git add -A
git commit -m "hardn 0.1.0"
gh repo create saideepreddy7781/hardn --public --source . --push
```

Then, on GitHub → **Settings**:
- **Code security** → enable *Private vulnerability reporting* (SECURITY.md points people there).
- **Environments** → **New environment** named `pypi` (optionally add yourself as a required reviewer,
  so every PyPI publish waits for your click).

Friends can already install it now:
`pipx install git+https://github.com/saideepreddy7781/hardn`

## 2. Connect PyPI with Trusted Publishing (one time, no API tokens)

1. Create an account at <https://pypi.org/account/register/> and enable 2FA.
2. Go to <https://pypi.org/manage/account/publishing/> → **Add a new pending publisher** → GitHub:
   - PyPI project name: `hardn`
   - Owner: `saideepreddy7781` · Repository: `hardn`
   - Workflow name: `release.yml` · Environment name: `pypi`

(Optional rehearsal: do the same on <https://test.pypi.org> and temporarily add
`with: { repository-url: https://test.pypi.org/legacy/ }` to the publish step.)

## 3. Release

```bash
# bump the version in hardn/__init__.py and add a CHANGELOG entry, then:
git commit -am "release 0.1.0"
git tag v0.1.0
git push origin main v0.1.0
```

Watch it under **Actions → release**. When it's green:
- `pipx install hardn` works for everyone
- <https://github.com/saideepreddy7781/hardn/releases> has binaries for Linux, macOS (Apple silicon), Windows

Move the major tag so `uses: saideepreddy7781/hardn@v0` picks up the release:

```bash
git tag -f v0 && git push -f origin v0
```

The workflow fails fast if the tag doesn't match `hardn.__version__`.

## 4. Optional: GitHub Marketplace (for the Action)

Edit the GitHub Release → tick **Publish this Action to the GitHub Marketplace** → accept the terms.
`action.yml` is already at the repo root.

## 5. Optional: Homebrew

```bash
gh repo create saideepreddy7781/homebrew-tap --public --clone && cd homebrew-tap
mkdir -p Formula && cp ../hardn/packaging/homebrew/hardn.rb Formula/
# set sha256 to the sdist hash from PyPI:
curl -s https://pypi.org/pypi/hardn/0.1.0/json \
  | python3 -c "import json,sys; print([u['digests']['sha256'] for u in json.load(sys.stdin)['urls'] if u['packagetype']=='sdist'][0])"
git add -A && git commit -m "hardn 0.1.0" && git push
```

Users: `brew install saideepreddy7781/tap/hardn`

## Notes for people using the binaries

- The binaries are **not code-signed**. On macOS, after downloading:
  `chmod +x hardn-macos-arm64 && xattr -d com.apple.quarantine hardn-macos-arm64`.
  Windows SmartScreen may warn on first run ("More info → Run anyway").
  `pipx install hardn` avoids both.
- Verify downloads: `shasum -a 256 -c SHA256SUMS --ignore-missing`.
