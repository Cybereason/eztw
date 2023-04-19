"""
Basic logger used throughout eztw.
Use enable_logging / disable_logging to enable or suppress.
"""
import logging

LOGGER = logging.getLogger("eztw")

def enable_logging():
    if not LOGGER.handlers:
        LOGGER.setLevel(logging.INFO)
        _formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s",
                                       datefmt="%d/%m/%Y %H:%M:%S")
        _log_console_handler = logging.StreamHandler()
        _log_console_handler.setLevel(logging.INFO)
        _log_console_handler.setFormatter(_formatter)
        LOGGER.addHandler(_log_console_handler)

def disable_logging():
    if LOGGER.handlers:
        LOGGER.handlers.clear()

enable_logging()
