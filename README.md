# TLSential
TLSential is a server for providing short-lived, non-wildcard domains to all services within a firewall restricted network.

# Building

Clone the repo. From the root directory, run `go build`. You should now have a binary in the root directory, `TLSential`.

# Running TLSential

You can run it with the default settings by just executing ./TLSential from the root directory. You can configure the server's port by using the `--port [port]` parameter.