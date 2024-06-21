"""A global configuration storage class that can be easily accessed."""

from typing import Any

from traffic_taffy.config import Config


class TT_CFG:
    LOG_LEVEL: str = "log_level"
    CACHE_RESULTS: str = "cache_results"


taffy_global_defaults = {"log_level": "info"}


class TaffyConfig(object):
    """A global configuration storage class that can be easily accessed."""

    _instance = None

    def __new__(class_obj, *args, **kwargs):
        if not isinstance(class_obj._instance, Config):
            class_obj._instance = Config(*args, **kwargs)
            class_obj._instance.update(taffy_global_defaults)
        return class_obj._instance


def taffy_default(parameter: str, value: Any) -> bool:
    """"""
    config = TaffyConfig()
    try:
        value = (
            config.get_dotnest(parameter, return_none=False) is not None
        )  # ignore any value
    except ValueError:
        # a value doesn't exist, so create it
        config.set_dotnest(parameter, value)
        return True

    if value is None:
        config.set_dotnest(parameter, value)
        return True

    return False
