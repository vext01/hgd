import time

def hgd_hook_init(ctx):
    """ test members """

    ctx.dprint(ctx.D_DEBUG, "testing dprint()");

    print("")
    print(80 * "-")
    print("HGD Scripting backend test!")
    print(80 * "-")

    print("HGD version is: %s" % ctx.hgd_version)
    print("HGD component is: %s" % ctx.component)
    print("protocol version is: %d" % ctx.proto_version)
    print("debug level is: %d" % ctx.debug_level)
    print("playlist:")
    for i in ctx.get_playlist():
        print("  " + str(i))

    print(80 * "-")
    print("")

    return 0

"""
load test api
def hgd_hook_pre_play(ctx):
    ctx.dprint(ctx.D_WARN,"test starting")

    for i in range(9000):
        l = ctx.get_playlist();

        if (i % 1000 == 0):
            time.sleep(1);
            ctx.dprint(ctx.D_INFO, "1000 pause")

    ctx.dprint(ctx.D_DEBUG, "DONE!")
    return 0
"""
