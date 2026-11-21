"""Assemble the GUI with the Windows Electrum 4.6.2 runtime."""
import marshal
from pathlib import Path
import struct
import sys
import zlib

from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter

folder = Path(__file__).resolve().parent
original = folder / "electrum.exe"
a = CArchiveReader(str(original))
with original.open("rb") as source:
    source.seek(a._end_offset - a._COOKIE_LENGTH)
    magic, _, _, _, py_version, py_library = struct.unpack(
        a._COOKIE_FORMAT, source.read(a._COOKIE_LENGTH),
    )
    assert py_version == sys.version_info.major * 100 + sys.version_info.minor
    target = Path(sys.argv[1])
    with target.open("wb") as output:
        source.seek(0)
        output.write(source.read(a._start_offset))
        package_start = output.tell()
        toc = [(0, 0, 0, 0, "o", option) for option in a.options]
        for name, (offset, size, raw_size, compressed, kind) in a.toc.items():
            if kind == "s" and not name.startswith(("pyiboot", "pyi_rth_")):
                continue
            toc.append((output.tell() - package_start, size, raw_size, compressed, kind, name))
            source.seek(a._start_offset + offset)
            output.write(source.read(size))
        script = folder / "walletgenerator.py"
        code = marshal.dumps(compile(script.read_bytes(), script.name, "exec"))
        compressed_code = zlib.compress(code, 9)
        toc.append((output.tell() - package_start, len(compressed_code), len(code), 1, "s", script.stem))
        output.write(compressed_code)
        table_offset = output.tell() - package_start
        table = CArchiveWriter._serialize_toc(toc)
        output.write(table)
        output.write(struct.pack(
            a._COOKIE_FORMAT, magic, table_offset + len(table) + a._COOKIE_LENGTH,
            table_offset, len(table), py_version, py_library,
        ))
