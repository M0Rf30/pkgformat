#!/usr/bin/env python3
"""Write what libmodulemd (python bindings) makes of each modules.yaml given:
the file is loaded into a ModuleIndex and dumped, to FILE.libmodulemd.yaml
next to it. The dump is the reference the Go writer is compared with."""
import sys

import gi

gi.require_version("Modulemd", "2.0")
from gi.repository import Modulemd  # noqa: E402

for path in sys.argv[1:]:
    index = Modulemd.ModuleIndex.new()
    ok, failures = index.update_from_file(path, True)
    if not ok:
        sys.exit("%s: %s" % (path, [f.get_gerror().message for f in failures]))
    out = path.removesuffix(".yaml") + ".libmodulemd.yaml"
    with open(out, "w", encoding="utf-8") as f:
        f.write(index.dump_to_string())
