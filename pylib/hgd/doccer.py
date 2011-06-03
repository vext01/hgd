"""
Generate Python API Docs
"""

import pydoc
import os
import sys

output_dir = "pydoc"

def hgd_mk_pydoc():

    if (not os.path.exists(output_dir)):
            os.mkdir(output_dir)

    # first make top level docs
    f = open("%s/index.html" % (output_dir), "w")

    d = pydoc.HTMLDoc()
    html = d.page("HGD Python API", d.docmodule(sys.modules["hgd"]))

    f.write(html)
    f.close()

    # now each module in the hgd package which is not builtin
    mods = ["hgd.playlist", "hgd.doccer"]

    for mod in mods:
        f = open("%s/%s.html" % (output_dir, mod), "w")
        html = d.page("HGD Python API", d.docmodule(sys.modules[mod]))
        f.write(html)
        f.close()

    return 0

if (__name__ == "__main__"):
    print("Don't run this script directly! Use the hgd-mk-pydoc binary")
