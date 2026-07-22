# Event handling tests

The event package reacts to Docker container lifecycle events and updates resolver configuration or CNI state.

Unit tests run without modifying the host. Namespace and resolver integration tests must run only on a disposable Linux VM with a dedicated Docker daemon; never point them at a workstation or production host.
