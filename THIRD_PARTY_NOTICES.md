# Third-Party Notices

This program includes Go dependencies recorded by `go.mod`, `go.sum`, and `vendor/modules.txt`. Exact license or notice texts are copied without modification under `LICENSES/` for source and container distributions. `LICENSES/modules.tsv` binds every vendored module version to the SHA-256 of its copied text.

The maintained dependency set includes the CNI project, Moby, Open Containers, Sirupsen, urfave, Vishvananda, OpenTelemetry, and supporting Go libraries. Licenses include Apache-2.0, MIT, and BSD-family terms as identified by the corresponding copied files.

The historical `go-rancher-metadata` snapshot did not contain an explicit license file at the pinned revision. Its code is therefore not included in the maintained tree; `internal/metadata` is a separately implemented client for the documented metadata HTTP contract.

The root [LICENSE](LICENSE) governs inherited project code and PastureStack modifications offered under the same terms. It does not replace third-party license texts.
