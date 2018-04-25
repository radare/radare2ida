#!/usr/bin/env python

import idb
import sys
import base64

def idb2r2_comments(api, textseg):
    for ea in range(textseg, api.idc.SegEnd(textseg)):
        try:
            flags = api.ida_bytes.get_cmt(ea, True)
            if flags != "":
                print("CCu base64:" + base64.b64encode(flags.encode(encoding='UTF-8')).decode("utf-8") + " @ " + str(ea))
        except Exception as e:
            try:
                flags = api.ida_bytes.get_cmt(ea, False)
                print("CCu base64:" + base64.b64encode(flags.encode(encoding='UTF-8')).decode("utf-8") + " @ " + str(ea))
            except:
                pass

def idb2r2_functions(api):
    for ea in api.idautils.Functions():
        print("af " + api.idc.GetFunctionName(ea).replace("@","_") + " @ " + str(ea))

with idb.from_file(sys.argv[1]) as db:
    api = idb.IDAPython(db)
    baddr = api.ida_nalt.get_imagebase()
    idb2r2_functions(api)
    segs = idb.analysis.Segments(db).segments
    for segment in segs.values():
        idb2r2_comments(api,segment.startEA)
    sys.stderr.write("Convertion done.\nExecute: r2 -i [output.r2] -B %s [filename]\n" % (hex(baddr)))
