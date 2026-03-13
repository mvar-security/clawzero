"""Embedded policy profile metadata for documentation and tooling."""

PROFILES = {
    "dev_balanced": {
        "shell.exec": "block",
        "filesystem.read": "profile_sensitive",
        "http.request": "allow",
        "credentials.access": "block",
        "tool.custom": "allow",
    },
    "dev_strict": {
        "shell.exec": "block",
        "filesystem.read": "allow /workspace only",
        "http.request": "block",
        "credentials.access": "block",
        "tool.custom": "annotate",
    },
    "prod_locked": {
        "shell.exec": "block",
        "filesystem.read": "allow /workspace/project only",
        "http.request": "allow localhost only",
        "credentials.access": "block",
        "tool.custom": "allow",
    },
}
