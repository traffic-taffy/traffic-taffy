from traffic_taffy.hooks import register_hook, call_hooks

into_hook = 1


def test_register_and_call_hook():
    @register_hook("testhook")
    def hook_callback():
        global into_hook
        into_hook += 1

    call_hooks("testhookDNE")
    assert into_hook == 1

    call_hooks("testhook")
    assert into_hook == 2


def test_register_and_call_hook_with_args():
    @register_hook("testhook_storage")
    def hook_callback(storage, key, value):
        storage[key] = value

    the_storage = {}

    call_hooks("testhook_storage", the_storage, "testkey", "testvalue")
    assert the_storage == {"testkey": "testvalue"}

    call_hooks("testhook_storage", the_storage, "otherkey", 4)
    assert the_storage == {"testkey": "testvalue", "otherkey": 4}


def test_register_and_call_hook_with_kwargs():
    @register_hook("testhook_storage")
    def hook_callback(storage={}, key=None, value=None):
        storage[key] = value

    the_storage = {}

    call_hooks(
        "testhook_storage", storage=the_storage, key="testkey", value="testvalue"
    )
    assert the_storage == {"testkey": "testvalue"}

    call_hooks("testhook_storage", key="otherkey", value=4, storage=the_storage)
    assert the_storage == {"testkey": "testvalue", "otherkey": 4}
