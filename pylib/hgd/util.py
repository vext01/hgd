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

""" 
Various Cruft
"""

__author__ = "Edd Barrett"

import sys
import inspect

def hgd_dbg(msg):
    """ Print debug messages """

    # get info from the frame
    line = inspect.currentframe().f_back.f_lineno
    filen = inspect.currentframe().f_back.f_code.co_filename
    meth = __name__

    sys.stderr.write("[Py %s:%s:%s]\n\t%s\n" % (filen, meth, line, msg))

if (__name__ == "__main__"):
    #print("Don't run this script directly! Use the hgd-mk-pydoc binary")
    hgd_dbg("This is a test Python warning test")
