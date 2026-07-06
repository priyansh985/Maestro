"""Console entry points."""
import sys

from .validate_threats import main as validate_main


def cli_validate() -> None:
    sys.exit(validate_main())
