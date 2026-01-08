# RedAudit v4.3.3 - Critical Fix: Data Integrity & UI

[![Ver en Español](https://img.shields.io/badge/Ver%20en%20Español-red?style=flat-square)](https://github.com/dorinbadea/RedAudit/blob/v4.3.3/docs/releases/RELEASE_NOTES_v4.3.3_ES.md)

This is a critical fix release that addresses a data integrity issue in the reporting pipeline (JSON artifact) and a visual glitch in the network discovery wizard.

This release supersedes v4.3.2 to ensure vulnerability findings are correctly attached to reporting artifacts.

## Fixed

### Data Integrity

- **Missing Vulnerabilities in JSON**: Fixed a bug where vulnerability findings from tools like Nikto and TestSSL were discovered but not correctly attached to the `Host` object internal structure. This resulted in empty `findings` arrays in JSON reports and incorrect Risk Scores (calculated as 0) despite the presence of vulnerabilities.

### UI / UX

- **Progress Bar Glitch**: Resolved a visual issue in the Wizard where the "heartbeat" status message (*"Net Discovery in progress..."*) was printing directly to stdout instead of the progress console, causing IP address lines to duplicate on screen.

## Changes

- **Core**: Updated `Host` model to include a dedicated `findings` field.
- **Auditor**: Refactored `scan_vulnerabilities_concurrent` to correctly map and attach findings to parent Host objects.
- **Reporting**: Updated JSON serialization to include the populated `findings` list.
