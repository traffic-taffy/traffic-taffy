"""A global configuration storage class that can be easily accessed."""

from traffic_taffy.config import Config


class TaffyConfig(object):
    """A global configuration storage class that can be easily accessed."""

    _instance = None

    def __new__(class_obj, *args, **kwargs):
        if not isinstance(class_obj._instance, Config):
            class_obj._instance = Config(*args, **kwargs)
        return class_obj._instance
