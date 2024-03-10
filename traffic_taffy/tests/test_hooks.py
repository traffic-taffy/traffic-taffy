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
