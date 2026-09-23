"""A base class for report containers."""


class Report:
    """A bogus base class for containers for typing"""

    def __post_init__(self, *args, **argcs):
        """Initialize an otherwise empty class"""
        self.field_header_names = {}
