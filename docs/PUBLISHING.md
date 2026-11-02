# Importing this tree into a new GitHub repository

Extract the ZIP into an empty directory. `README.md`, `src/`, `docs/`,
`scripts/`, `upstream/` and `third_party/` should be directly inside that
directory. The package contains full dependency sources, so there is no
submodule initialization or separate source download.

Read [LICENSING.md](LICENSING.md) before choosing a repository license or
publishing compiled releases. Do not replace the component-license index with
a blanket license that claims third-party permissions you do not hold.

Create an empty repository named `pppd` in your own GitHub account. Leave its
initial README, license and `.gitignore` unchecked because this tree already
contains those files. With Git installed, run these commands from the
extracted directory, replacing `YOUR-ACCOUNT` with your actual account:

```sh
git init
git branch -M main
git add .
git add -f src upstream/ppp third_party/openssl-3.5.9
git status --short
git commit -m "Import partial Windows pppd port and complete build sources"
git remote add origin https://github.com/YOUR-ACCOUNT/pppd.git
git push -u origin main
```

Authenticate with your own GitHub credentials when Git requests them. These
are instructions for the repository owner; the packaging process does not
create a repository, commit to your account or push anything.

Use Git for the full source tree rather than dragging thousands of files into
the GitHub web uploader. Complete upstream dependency test data, including
public sample keys/certificates, is deliberately retained. No private lab
credentials or signing keys are required. `.gitignore` excludes local build
outputs and runtime configuration without hiding upstream source fixtures.
The second `git add` preserves all imported source files even if a retained
upstream `.gitignore` matches files supplied in its own release archive.

The optional GitHub Actions workflow compiles and runs information-only
checks. It does not operate hardware or upload combined executable artifacts.
