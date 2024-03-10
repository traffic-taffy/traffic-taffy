from collections import defaultdict

# __path__ = extend_path(__path__, __name__)

from functools import wraps

hooks = defaultdict(list)


def register_hook(hook):
    def decorator(function):
        hooks[hook].append(function)

        @wraps(function)
        def _wrap(*args, **kwargs):
            return function(*args, **kwargs)

        return _wrap

    return decorator


def call_hooks(spot, *args, **kwargs):
    for hook in hooks[spot]:
        hook(*args, **kwargs)


def main():
    @register_hook("hookspot")
    def test_hook():
        print("world!!!")

    print("hello")
    call_hooks("hookspot")


if __name__ == "__main__":
    main()
