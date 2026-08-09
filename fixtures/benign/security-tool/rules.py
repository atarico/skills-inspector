PATTERNS = [
    {"regex": r"(?<![a-zA-Z0-9_\.])eval\(",
     "reminder": "Warning: eval() executes arbitrary code."},
    {"regex": r"curl[^|]*\|\s*sh",
     "reminder": "Piping a download into a shell is unreviewable."},
]
