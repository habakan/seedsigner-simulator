"""
bitwasm_signer.wamr, with the browser's own WebAssembly engine in place of WAMR.

The device drives parser.wasm and signer.wasm through libiwasm and ctypes, and
neither exists in Pyodide. The page's engine runs the same modules, so this
module takes the place of bitwasm_signer.wamr in sys.modules before the wallet
imports it, and everything above it -- signer.py and the wallet -- is unchanged.

Same interface as the original: Instance(wasm) has no imports, calls exports as
functions of i32 arguments returning a signed i32, and exposes `memory`.
"""

from js import Uint8Array, WebAssembly
from pyodide.ffi import JsException, to_js


class Memory:
    """The instance's linear memory as signer.py uses it: indexing, slice reads
    and writes, len(), and the buffer protocol for struct.unpack_from.

    The bytes live in a JS ArrayBuffer that Python cannot alias, so the buffer
    protocol hands out a copy. That is enough for the reads it is used for."""

    def __init__(self, buffer):
        self._view = Uint8Array.new(buffer)

    def __len__(self):
        return self._view.length

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, _ = key.indices(self._view.length)
            return self._view.subarray(start, stop).to_bytes()
        return self._view[key]

    def __setitem__(self, key, data):
        if isinstance(key, slice):
            start, stop, _ = key.indices(self._view.length)
            if stop - start != len(data):
                raise ValueError("memory slice assignment cannot change the size")
            self._view.set(to_js(bytes(data)), start)
        else:
            self._view[key] = data

    def __buffer__(self, flags):
        return memoryview(self._view.to_bytes())


class Instance:
    def __init__(self, wasm: bytes, lib_path=None):
        module = WebAssembly.Module.new(to_js(bytes(wasm)))
        if WebAssembly.Module.imports(module).length:
            raise RuntimeError("the module must have no imports")
        self._exports = WebAssembly.Instance.new(module).exports
        # Neither module grows its memory, so this view stays valid
        self.memory = Memory(self._exports.memory.buffer)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        f = getattr(self._exports, name, None)
        if f is None or not callable(f):
            raise AttributeError(f"no export {name}")

        def call(*args):
            try:
                result = f(*((a + 2**31) % 2**32 - 2**31 for a in args))
            except JsException as e:
                raise RuntimeError(str(e)) from None
            # A void export returns undefined, and nothing reads its result
            return 0 if result is None else int(result)
        return call
