#!/usr/bin/env python3
"""Disk Image Acquisition & Hashing Toolkit (DIHT) - shared configuration."""

APP_NAME = "Disk Image Acquisition & Hashing Toolkit"
APP_SHORT = "DIHT"
VERSION = "1.0.0"
BUILD_DATE = "2026-09-20"

# Supported digest algorithms (FIPS / NIST aligned).
# sha256 + sha3_256 are the authoritative integrity pair.
ALGORITHMS = {
    "md5":        ("MD5 (legacy)", True),
    "sha1":       "SHA-1 (legacy)",
    "sha256":     "SHA-256 (FIPS 180-4)",
    "sha3_256":   "SHA3-256 (primary)",
    "blake2b":    "BLAKE2b-256",
}
AUTHORITATIVE = ["sha256", "sha3_256"]

# Streaming read block for hashing & imaging.
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB

# Physical device name prefix on Windows
WIN_PREFIX = r"\\.\PhysicalDrive"

# Raw image extension used by the portable tool.
RAW_EXT = "dd"
MANIFEST_NAME = "evidence_manifest.json"
CUSTODY_NAME = "chain_of_custody.json"
SHA256SUMS_NAME = "SHA256SUMS"
REPORT_PDF_NAME = "forensic_report.pdf"
REPORT_PDFA_NAME = "forensic_report_pdfa.pdf"
EXPORT_XLSX_NAME = "hash_manifest.xlsx"
EXPORT_CSV_NAME = "hash_manifest.csv"
CUSTODY_PDF_NAME = "chain_of_custody_report.pdf"

# Report metadata
ORG_DEFAULT = "Cyber Forensics Unit"
ISO_REFS = "ISO/IEC 27001:2022, ISO/IEC 27037:2012, ISO/IEC 27042:2015, NIST SP 800-86, NIST SP 800-101, ACPO"

LEDGER_V1 = 1