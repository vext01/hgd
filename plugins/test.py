"""
Test the scripting backend
"""
def hgd_hook_init(hgd):

    if (hgd.debug_level >= 2):
        print("")
        print(80 * "-")
        print("HGD Scripting backend test!")
        print(80 * "-")

        print("HGD version is: %s" % hgd.hgd_version)
        print("HGD component is: %s" % hgd.component)
        print("protocol version is: %d" % hgd.proto_version)
        print("debug level is: %d" % hgd.debug_level)
        print("playlist: %s" % str(hgd.get_playlist()))

        hgd.mod_data["test"] = "this is where modules can store things";
        print("mod_data: %s" % hgd.mod_data);

        print(80 * "-")
        print("")

    return 0
