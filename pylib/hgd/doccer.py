# Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

""" Generate Python API Docs.

This class generates docs for the HGD Python API. This is non-trivial, as
the core 'Hgd' type is only available in the embedded interpreter. Hence
the hgd-mk-pydoc embeds Python, defines the types and then uses this module
to make documentation.
"""

__author__ = "Edd Barrett"

import pydoc
import os
import sys


def hgd_mk_pydoc():
    """ Generate HGD Python documentation """

    outdir = "pydoc"
    if (not os.path.exists(outdir)):
        os.mkdir(outdir)

    # HTML doc disabled for now
    #for doctype in ["txt", "html"]:
    for doctype in ["txt"]:

        if (not os.path.exists(outdir + "/" + doctype)):
            os.mkdir(outdir + "/" + doctype)

        if (doctype == ("txt")):
            d = pydoc.TextDoc()
        else:
            d = pydoc.HTMLDoc()

        # first make top level docs
        f = open("%s/%s/index.%s" % (outdir, doctype, doctype), "w")

        if (doctype == "html"):
            content = d.page("HGD Python API", d.docmodule(sys.modules["hgd"]))
        else:
            content = d.docmodule(sys.modules["hgd"])

        f.write(content)
        f.close()

        # now each module in the hgd package which is not builtin
        mods = ["hgd.playlist", "hgd.doccer"]

        for mod in mods:
            f = open("%s/%s/%s.%s" % (outdir, doctype, mod, doctype), "w")

            if (doctype == "html"):
                content = d.page("HGD Python API", d.docmodule(sys.modules[mod]))
            else:
                content = d.docmodule(sys.modules[mod])

            f.write(content)
            f.close()

    return 0

if (__name__ == "__main__"):
    print("Don't run this script directly! Use the hgd-mk-pydoc binary")
