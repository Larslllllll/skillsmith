# Troubleshooting: PyPI Trusted Publishing

If the publish workflow fails with a 403 from PyPI, the most common
cause is that trusted publishing hasn't been configured yet on pypi.org.

## One-time setup (pypi.org)

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new pending publisher:
   - Owner: `Larslllllll`
   - Repository: `skillsmith`
   - Workflow filename: `publish.yml`
   - Environment name: (leave blank, or use `pypi` if you prefer)
3. Save. The first release will then be able to publish.

## First release

```bash
# locally
cd /home/pilars/moneymaker-mission/skillsmith
# verify version
grep '^version' pyproject.toml
# tag and push
git tag v0.3.1
git push origin v0.3.1
# then create a release on github.com/Larslllllll/skillsmith/releases
# (the workflow triggers on release: { types: [published] })
```

## Re-running without a new release

If the first publish fails (e.g. misconfigured trusted publisher),
the workflow will not re-run on the same release tag. Options:
- Re-tag (delete v0.3.1, re-create v0.3.1, push again, re-publish release)
- Manually trigger from the Actions tab (use `workflow_dispatch` if added)

## Version bumps

Edit `pyproject.toml` and `skillsmith/__init__.py` together. The
`tests/test_version.py` checks they stay in sync and the smoke-test
in `publish.yml` greps for the version in `--version` output.
