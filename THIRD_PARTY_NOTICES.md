# Third-Party Notices

This program includes vendored Go dependencies. Their source revisions are recorded in `trash.conf`, and exact license or notice texts are copied without modification under `LICENSES/` for source and container distributions.

The dependency set includes components from Azure, Microsoft, the CNI project, Docker and Moby, Open Containers, HashiCorp, Sirupsen, urfave, Vishvananda, the Go project, and historical control-plane client libraries. Licenses include Apache-2.0, MIT, BSD-family terms, MPL-2.0, notices, and Go patent grants as identified by the corresponding copied files.

The historical `go-rancher-metadata` snapshot did not contain an explicit license file at the pinned revision. Its code is therefore not included in the maintained tree; `internal/metadata` is a separately implemented client for the documented metadata HTTP contract.

The root [LICENSE](LICENSE) governs inherited project code and PastureStack modifications offered under the same terms. It does not replace third-party license texts.
