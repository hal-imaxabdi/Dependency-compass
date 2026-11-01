from dependency_compass.ratelimit import RateLimiter


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_per_client_limit_and_retry_after():
    clock = Clock()
    rl = RateLimiter(per_client=2, global_limit=100, window=60, clock=clock)
    assert rl.check("a") is None
    clock.now += 10
    assert rl.check("a") is None
    clock.now += 5
    assert rl.check("a") == 45          # first hit leaves the window in 45s
    assert rl.check("b") is None        # other clients unaffected


def test_window_slides():
    clock = Clock()
    rl = RateLimiter(per_client=1, global_limit=100, window=60, clock=clock)
    rl.check("a")
    clock.now += 60
    assert rl.check("a") is None


def test_global_limit_applies_across_clients():
    clock = Clock()
    rl = RateLimiter(per_client=10, global_limit=2, window=60, clock=clock)
    assert rl.check("a") is None and rl.check("b") is None
    assert rl.check("c") == 60


def test_rejected_requests_do_not_consume_quota():
    clock = Clock()
    rl = RateLimiter(per_client=1, global_limit=100, window=60, clock=clock)
    rl.check("a")
    for _ in range(5):
        rl.check("a")
    clock.now += 60
    assert rl.check("a") is None


def test_tracked_clients_are_bounded():
    rl = RateLimiter(per_client=1, global_limit=1000, max_clients=3, clock=Clock())
    for ip in "abcde":
        rl.check(ip)
    assert len(rl._clients) == 3
    assert rl.check("a") is None        # oldest was forgotten
