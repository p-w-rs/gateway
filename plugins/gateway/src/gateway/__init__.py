"""gateway: one audited path for network, credential, and certificate work."""
# Kept equal to .claude-plugin/plugin.json's "version" (the MCP server's
# serverInfo and tests/test_release.py check it): a release that bumps one
# bumps both, so the gw server never reports a stale version after an update.
__version__ = "0.10.0"
