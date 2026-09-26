"""Brand palette shared by report generators."""

# Solid brand colors (hex, no '#')
BRAND_BLUE = "1D4ED8"
BRAND_TEAL = "0D9488"
BRAND_INDIGO = "3730A3"
BRAND_VIOLET = "7C3AED"
BRAND_PINK = "B02572"
BRAND_SLATE = "13795B"

HEADER_BG = "212529"      # near-black for table headers
TEXT_DARK = "212529"

# Severity bands (kept in sync with models.cvss.Severity.hex_color)
SEVERITY_COLORS = {
    "Critical": "#E03131",
    "High": "#F76707",
    "Medium": "#FAB005",
    "Low": "#40C057",
    "None": "#868E96",
}