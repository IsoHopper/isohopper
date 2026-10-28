# Security

IsoHopper is **super experimental and pending human testing**. Physical disk writes are disabled. Current disk-image creation writes only new regular files; host device inspection is read only.

Report suspected vulnerabilities to [dev@charlie.fyi](mailto:dev@charlie.fyi). Include the affected version or commit, operating system, command or screen, expected behavior, actual behavior, and a minimal reproduction when possible.

Use synthetic files and redact private device identifiers, paths, credentials, and personal data. Please avoid posting exploit details or sensitive logs in a public issue before contacting the maintainer.

Areas of particular interest include path traversal, symlink races, unintended file replacement, malformed image parsing, incorrect device authorization, and misleading verification results. A calculated checksum alone does not establish publisher authenticity, Secure Boot compatibility, or successful operating-system boot.
