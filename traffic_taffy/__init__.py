import traceback
from logging import warning

__VERSION__ = "1.8"


def print_version():
    print(f"Traffic-Taffy: {__VERSION__}")
    print("Documentation: https://traffic-taffy.github.io/")
    exit(0)


def main_wrapper(main_func: callable):
    try:
        main_func()
    except BrokenPipeError:
        # catch pipes to head/etc
        print("here")
        return
    except Exception:
        warning(traceback.format_exc())
