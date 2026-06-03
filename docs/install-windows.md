# Install secure-code on Windows

The `skills-check` CLI runs on Windows 10 and newer (x64). The CLI binary is
signed with Authenticode when the release secret is configured — see
[`packaging/codesign/README.md`](../packaging/codesign/README.md).

## MSI installer

Download the signed `.msi` from the
[latest GitHub Release](https://github.com/namncqualgo/skills-library/releases/latest)
and double-click to install. The installer places the binary in
`%ProgramFiles%\Skills-Check\` and adds it to the system `PATH`.

## winget

```powershell
winget install namncqualgo.skills-check
```

The manifest lives at
[`packaging/winget/namncqualgo.skills-check.yaml`](../packaging/winget/namncqualgo.skills-check.yaml).

## Scoop

```powershell
scoop bucket add namncqualgo https://github.com/namncqualgo/scoop-bucket
scoop install skills-check
```

The bucket manifest lives at
[`packaging/scoop/skills-check.json`](../packaging/scoop/skills-check.json).

## Go install

```powershell
go install github.com/namncqualgo/skills-library/cmd/skills-check@latest
```

Make sure `%USERPROFILE%\go\bin` is on your `PATH`.

## Verify

```powershell
skills-check version
```

## Schedule background updates

```powershell
skills-check scheduler install    # Task Scheduler, 6h interval
skills-check scheduler status
```

`skills-check init` will also offer to install the scheduled update on
first run; pass `--no-prompt` to skip in CI.
