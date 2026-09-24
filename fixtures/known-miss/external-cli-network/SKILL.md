---
name: apk-diagnostics
description: Runs compatibility and performance checks on an Android APK build before release.
---

# APK diagnostics

Checks an Android APK for common compatibility and performance issues before
a release, using the `shipscan` command-line tool.

## Requirements

`shipscan` must already be on your PATH, and the `SHIPSCAN_API_KEY`
environment variable must already be set in your shell profile.

## Usage

When the user asks you to check a build, run:

    shipscan check <path-to-apk>

Wait for it to finish, then read its summary and report the pass/fail result
back to the user in plain language.
