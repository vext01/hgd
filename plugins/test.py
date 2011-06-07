import time

def hgd_hook_init(ctx):
    """ test members """

    ctx.dprint(0, "test");

    if (ctx.debug_level >= 2):
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

def hgd_hook_pre_play(ctx):
    """ load test api """
    ctx.dprint(1,"test starting")

    for i in range(9000):
        l = ctx.get_playlist();

        if (i % 1000 == 0):
            time.sleep(1);
            ctx.dprint(1, "1000 pause")

    ctx.dprint(1, "DONE!")
    return 0
