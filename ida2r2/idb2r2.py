#!/usr/bin/env python

""" Export IDB from IDA into a radare2 script

$ idb2r2.py -h

usage: idb2r2.py [-h] -f IDB_FILE -o OUT_FILE [-nc | -nf]

Export IDB from IDA into a radare2 initialization script

optional arguments:
  -h, --help            show this help message and exit
  -f IDB_FILE, --IDBFile IDB_FILE
                        Path to the IDB file
  -o OUT_FILE, --OutputFile OUT_FILE
                        Export to a specified file path
  -nc, --no-comments    Don't convert comments
  -nf, --no-functions   Don't convert functions

"""

__author__ = "Maxime Morin (@maijin), Itay Cohen (@megabeets_)"


import argparse
import idb
import sys
import base64


def get_args():
    ''' Handle arguments using argparse
    '''

    arg_parser = argparse.ArgumentParser(
        description="Export IDB from IDA into a radare2 initialization script")

    arg_parser.add_argument("-f", "--IDBFile",
                            action="store",
                            dest="idb_file",
                            required=True,
                            help="Path to the IDB file")

    arg_parser.add_argument("-o", "--OutputFile",
                            action="store",
                            dest="out_file",
                            required=True,
                            help="Export to a specified file path")

    arg_group = arg_parser.add_mutually_exclusive_group()

    arg_group.add_argument("-nc", "--no-comments",
                           dest="is_comments",
                           action="store_false",
                           help="Don't convert comments")

    arg_group.add_argument("-nf", "--no-functions",
                           dest="is_functions",
                           action="store_false",
                           help="Don't convert functions")

    arg_parser.set_defaults(is_comments=True, is_functions=True)

    args = arg_parser.parse_args()
    return args


def idb2r2_comments(api, textseg):
    ''' Convert comments from a specific text segments in the IDB
    '''

    for ea in range(textseg, api.idc.SegEnd(textseg)):
        try:
            flags = api.ida_bytes.get_cmt(ea, True)
            if flags != "":
                outfile.write("CCu base64:" + base64.b64encode(flags.encode(
                    encoding='UTF-8')).decode("utf-8") + " @ " + str(ea) + "\n")
        except Exception as e:
            try:
                flags = api.ida_bytes.get_cmt(ea, False)
                outfile.write("CCu base64:" + base64.b64encode(flags.encode(
                    encoding='UTF-8')).decode("utf-8") + " @ " + str(ea) + "\n")
            except:
                pass


def idb2r2_functions(api):
    ''' Convert all functions from the IDB
    '''

    for ea in api.idautils.Functions():
        outfile.write(
            "af " + api.idc.GetFunctionName(ea).replace("@", "_") + " @ " + str(ea) + "\n")


def main():
    ''' Gets arguments from the user. Perform convertion of the chosen data from the IDB into a radare2 initialization script
    '''

    global outfile
    args = get_args()
    with idb.from_file(args.idb_file) as db:
        api = idb.IDAPython(db)
        baddr = api.ida_nalt.get_imagebase()
        outfile = open(args.out_file, 'w')

        print("[+] Starting convertion from '%s' to '%s'" %
              (args.idb_file, args.out_file))

        if args.is_functions:
            idb2r2_functions(api)

        if args.is_comments:
            segs = idb.analysis.Segments(db).segments
            for segment in segs.values():
                idb2r2_comments(api, segment.startEA)

    print("[+] Convertion done.\n")
    print("[!] Execute: r2 -i %s -B %s [program]\n" %
          (args.out_file, hex(baddr)))


if __name__ == "__main__":
    main()
