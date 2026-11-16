# Private DEV package publishing

The private OpenPhysical GitHub Packages feed supplies the DEV `Gp4Net` package pinned by OpenPhysical product repositories. This manual workflow is separate from the existing tagged NuGet.org publisher; it does not change public package visibility or publish to NuGet.org.

Run `Publish immutable DEV NuGet packages` only after the exact source commit has passed the normal source review and tests. Provide the full source SHA and the exact DEV version required by consumers. The workflow requires that commit to be an ancestor of the repository default branch, restores, builds, and tests it, then packs `Gp4Net` with the consumer-pinned version override. That override is intentional: `version.json` remains the public release version source, while the private DEV version is an explicit dependency pin.

Before push, the workflow creates a manifest binding package ID, version, source commit, archive SHA-256, each archive entry, and native/model inventory. It rejects an existing package ID/version, so GitHub Packages' immutable version rule is enforced without `--skip-duplicate`. The workflow uses its `GITHUB_TOKEN` with `packages: write`; no PAT is required.

## Consumer access

The `OpenPhysical` organization owner must grant Actions package read access to each private consumer repository that restores `Gp4Net`: `OpenPhysical.Net`, `OpenPhysical.Biometrics`, `OpenPhysical.Enrollment.Studio`, `OpenPhysical.Issuer.Studio`, `OpenPhysical.Issuance.Server`, and `OpenPhysical.Directory`. These grants are required and are not asserted as configured here. Consumer workflows also need a `GITHUB_TOKEN` with `packages: read` and explicit NuGet source credentials for the `openphysical` source.

Publish this package before publishing Net, Bio, Issuer, or product pins that depend on it. Net's `Gp4NetSourceRevision` must match the final published source commit. The current bootstrap package evidence does not establish a published GitHub Packages artifact.
