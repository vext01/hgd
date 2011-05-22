"""
Test the scripting backend
"""
def hgd_hook_init(hgd):

    if (hgd.debug_level >= 2):
        print("\n---------------------------")
        print("HGD Scripting backend test!")
        print("---------------------------")
        print("protocol version is: %d" % hgd.proto_version)
        print("debug level is: %d" % hgd.debug_level)
        print("playlist: %s" % str(hgd.get_playlist()))
        print("---------------------------\n")

    return 0
