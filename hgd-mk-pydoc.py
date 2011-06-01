"""
Generate Python API Docs
"""

import pydoc
import sys

def hgd_hook_mk_pydoc(ctx):
    f = open("doc.html", "w")
    print(sys.modules["hgd"])
    d = pydoc.HTMLDoc()

    html = d.page("HGD Python API", d.docmodule(sys.modules["hgd"]));
    f.write(html)
    f.close()
    return 0

if (__name__ == "__main__"):
    print("Don't run this script directly! Use the hgd-mk-pydoc binary")
