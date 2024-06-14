"""A global configuration storage class that can be easily accessed."""

from typing import Any

from traffic_taffy.config import Config


class TaffyConfig(object):
    """A global configuration storage class that can be easily accessed."""

    _instance = None

    def __new__(class_obj, *args, **kwargs):
        if not isinstance(class_obj._instance, Config):
            class_obj._instance = Config(*args, **kwargs)
        return class_obj._instance


def taffy_default(parameter: str, value: Any) -> bool:
    """"""
    config = TaffyConfig()
    try:
        value = config.get_dotnest(parameter) is not None  # ignore any value
    except ValueError:
        # a value doesn't exist, so create it
        config.set_dotnest(parameter, value)
        return True

    if value is None:
        config.set_dotnest(parameter, value)
        return True

    return False
