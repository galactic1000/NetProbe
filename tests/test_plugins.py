import socket

import netprobe.fingerprint as fp
import netprobe.protocol_plugins.builtin as pb
from netprobe.models import PortResult


def test_register_protocol_probe_override():
    def fake_http(target, port, timeout, af=socket.AF_INET):
        return "HTTP/1.1 200 OK\r\nServer: UnitTest/1.0\r\n\r\n"

    fp.register_protocol_probe("http", fake_http)
    pr = PortResult(port=80, state="open")
    fp.identify_service("127.0.0.1", pr, 0.1)
    assert pr.service == "http"
    assert "HTTP/1.1" in pr.banner


def test_list_protocol_probes_common_services():
    services = fp.list_protocol_probes()
    assert "http" in services
    assert "ssh" in services
    assert "redis" in services
    assert "memcached" in services
    assert "mqtt" in services
    assert "amqp" in services
    assert "vnc" in services


def test_grab_banner_uses_ipv6_sockaddr(mocker):
    seen = {"addr": None}

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, _):
            return None

        def connect(self, addr):
            seen["addr"] = addr

        def recv(self, _):
            return b"banner"

    mocker.patch.object(fp.builtins.socket, "socket", new=lambda *args, **kwargs: FakeSock())
    banner = fp.grab_banner("::1", 22, 0.1, af=socket.AF_INET6)
    assert "banner" in banner
    assert seen["addr"] == ("::1", 22, 0, 0)


def test_identify_service_infers_redis_banner(mocker):
    mocker.patch.object(fp, "grab_banner", new=lambda *args, **kwargs: "redis_version:7.2.4\r\nrole:master")
    pr = PortResult(port=65000, state="open")
    fp.identify_service("127.0.0.1", pr, 0.1)
    assert pr.service == "redis"
    assert pr.version == "Redis 7.2.4"


def test_http_probe_falls_back_get_on_inconclusive_head(mocker):
    calls = {"n": 0}

    def fake_active_probe(*args, **kwargs):
        calls["n"] += 1
        return "not-http" if calls["n"] == 1 else "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"

    mocker.patch.object(pb, "active_probe", new=fake_active_probe)
    out = pb.http_probe("127.0.0.1", 80, 0.1, use_ssl=False)
    assert calls["n"] == 2
    assert "HTTP/1.1 200 OK" in out
