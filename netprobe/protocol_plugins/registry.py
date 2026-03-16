"""Protocol probe plugin registry."""

from dataclasses import dataclass, field
from importlib import import_module
from typing import Callable


@dataclass
class PluginSpec:
    module: str
    name: str
    handler: Callable | None = None
    kwargs: dict = field(default_factory=dict)


class ProtocolProbeRegistry:
    def __init__(self):
        self._plugins: dict[str, PluginSpec] = {}

    def register(self, service: str, module: str, name: str, **kwargs) -> None:
        self._plugins[service] = PluginSpec(module=module, name=name, kwargs=kwargs)

    def register_callable(self, service: str, handler: Callable, **kwargs) -> None:
        self._plugins[service] = PluginSpec(
            module=handler.__module__,
            name=handler.__name__,
            handler=handler,
            kwargs=kwargs,
        )

    def get(self, service: str) -> PluginSpec | None:
        return self._plugins.get(service)

    def services(self) -> list[str]:
        return sorted(self._plugins.keys())

    def probe(self, service: str, target: str, port: int, timeout: float, af: int):
        spec = self.get(service)
        if not spec:
            return ""
        if spec.handler is not None:
            fn = spec.handler
        else:
            mod = import_module(spec.module)
            fn = getattr(mod, spec.name)
        return fn(target, port, timeout, af=af, **spec.kwargs)


PROBE_REGISTRY = ProtocolProbeRegistry()
