"""Log Anonymizer with Redactor for safe log sharing.

Security-aligned anonymization pipeline (OWASP Top 10, NIST CSF/SP 800-53,
ISO 27001:2022). Modules:

    core        - shared data models (classifications, strategies)
    detection   - multi-layer sensitive-data detection
    redaction   - seven redaction strategies
    security    - audit trail, tamper-evident hashing, input validation
    services    - policy engine and orchestration service
    api         - FastAPI REST interface
    config      - runtime configuration
"""

__version__ = "1.0.0"
