#!/bin/sh
# Chain to the deployment's own egress proxy when it has one.
#
# The upstream is configuration, not a build input: a deployment with direct
# egress leaves CAIRN_UPSTREAM_PROXY unset and the proxy resolves and connects
# on its own. Where the only route out is an HTTP proxy — as in a WSL or
# corporate setup — this is what reaches it, and the build sandbox still sees
# nothing but this container.
set -eu

CONFIG=/tmp/tinyproxy.conf
cp /etc/tinyproxy/tinyproxy.conf "$CONFIG"

if [ -n "${CAIRN_UPSTREAM_PROXY:-}" ]; then
    printf '\nupstream http %s\n' "${CAIRN_UPSTREAM_PROXY}" >> "$CONFIG"
    echo "cairn-dependency-proxy: forwarding through ${CAIRN_UPSTREAM_PROXY}" >&2
else
    echo "cairn-dependency-proxy: connecting directly" >&2
fi

exec tinyproxy -d -c "$CONFIG"
