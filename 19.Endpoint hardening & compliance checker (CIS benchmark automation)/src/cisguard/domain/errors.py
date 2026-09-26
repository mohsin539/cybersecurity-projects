"""Domain error taxonomy."""


class CGError(Exception):
    """Base for all CISGuard errors."""


class UserError(CGError):
    """Bad user input — actionable message."""


class CollectorError(CGError):
    """A collector failed to read system state (permissions, missing API)."""


class ReportError(CGError):
    pass
