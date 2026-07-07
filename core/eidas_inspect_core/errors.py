class EidasInspectError(Exception):
    """Base class for all typed errors raised by eidas_inspect_core."""


class CorruptedPdfError(EidasInspectError):
    """The input could not be parsed as a well-formed PDF."""


class PasswordRequiredError(EidasInspectError):
    """The PDF is encrypted and no password was supplied."""


class IncorrectPasswordError(EidasInspectError):
    """The PDF is encrypted and the supplied password did not decrypt it."""
