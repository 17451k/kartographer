# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 ISPRAS (http://www.ispras.ru)
# Institute for System Programming of the Russian Academy of Sciences
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import errno
import json
import multiprocessing
import os
import re
import shutil
import signal
import stat
import subprocess
import sys

# For parallel build
processes = multiprocessing.cpu_count()

realdir = os.path.dirname(os.path.realpath(__file__))
cwd = os.getcwd()

common = realdir + "/common.py"
config = realdir + "/config.json"
raw_cmds = cwd + "/raw_cmds.txt"
json_cmds = cwd + "/cmds.json"

args = dict()
cmds = dict()
final_cmds = dict()
cfg = dict()


def check_arguments(args):
    if not os.path.exists(common):
        sys.exit("Crucial part of this script - file common.py - does not exist")

    if not os.path.exists(config):
        sys.exit("Crucial part of this script - file config.json - does not exist")

    if not os.path.exists(args.sources):
        sys.exit("Path to sources does not exist")

    for path in args.stubs:
        if not os.path.exists(path):
            sys.exit("The paths specified in --stubs argument do not exist")


def parse_config():
    global cfg

    with open(config, "r") as config_fh:
        cfg = json.load(config_fh)


def create_stubs(stubs):
    for path in stubs:
        os.chdir(path)

        if path is not stubs[0]:
            shutil.copy(common, ".")

        for cmd in cfg["stubs"]:
            if os.path.exists(cmd):
                os.rename(cmd, cmd + ".bce")

            create_stub(cmd)


def create_stub(stub):
    with open(stub, "w") as cmd_fh:
        if sys.platform == "linux":
            cmd_fh.write("#!/usr/bin/python3\n")
        elif sys.platform == "darwin":
            cmd_fh.write("#!/usr/local/bin/python3\n")
        cmd_fh.write("import sys\n")
        cmd_fh.write("import common\n")
        cmd_fh.write("sys.exit(common.process(sys.argv))\n")

    st = os.stat(stub)
    os.chmod(stub, st.st_mode | stat.S_IEXEC)


def remove_stubs(stubs):
    for path in stubs:
        os.chdir(path)

        for cmd in cfg["stubs"]:
            silentremove(cmd)

            if os.path.exists(cmd + ".bce"):
                os.rename(cmd + ".bce", cmd)

        if path is not stubs[0]:
            silentremove("common.py")

        if os.path.exists("__pycache__"):
            shutil.rmtree("__pycache__")


def build_src(src):
    stubs = [os.path.abspath(stub) for stub in args.stubs]
    silentremove(raw_cmds)

    env = dict(os.environ)
    env.update({"RAW_CMDS": raw_cmds})

    create_stubs(stubs)
    env.update({"PATH": "{0}:{1}".format(stubs[0], os.environ["PATH"])})
    os.chdir(src)

    subprocess.call(args.make.split(), env=env)

    remove_stubs(stubs)
    os.chdir(cwd)


def process_raw_cmds(src):
    cmds["build commands"] = []
    cmds["src"] = src

    with open(raw_cmds, "r") as cmd_fh:
        for line in cmd_fh:
            line = re.sub(r"\n", "", line)
            opts = line.split("||")

            cmd = dict()
            cmd["in"] = []
            cmd["out"] = None
            cmd["opts"] = []
            cmd["cwd"] = opts.pop(0)
            cmd["type"] = opts.pop(0)

            in_files_are_required = True
            out_file_is_required = True

            if cmd["type"] in ("cc", "ld"):
                opts_requiring_vals = cfg["opts_info"][cmd["type"]]["require values"]
                skip_next_opt = False

                if len(opts) == 0:
                    continue

                for index, opt in enumerate(opts):
                    # Option represents already processed value of the previous option.
                    if skip_next_opt:
                        skip_next_opt = False
                        continue

                    if opt in cfg["opts_info"][cmd["type"]]["do not require in, out and values"]:
                        in_files_are_required = False
                        out_file_is_required = False
                        cmd["opts"].append(opt)
                        continue

                    for does_not_requre_in in cfg["opts_info"][cmd["type"]]["do not require in"]:
                        if re.search(r"^-{}".format(does_not_requre_in), opt):
                            in_files_are_required = False

                    for does_not_requre_out in cfg["opts_info"][cmd["type"]]["do not require out"]:
                        if re.search(r"^-{}".format(does_not_requre_out), opt):
                            out_file_is_required = False

                    # Options with values.
                    match = None
                    for opt_requiring_val in opts_requiring_vals:
                        match = re.search(r"^({})(=?)(.*)".format(opt_requiring_val), opt)
                        if match:
                            opt, eq, val = match.groups()

                            # Option value is specified by means of the following option.
                            if not val:
                                val = opts[index + 1]
                                skip_next_opt = True

                            # Workaround for cc commads, that does not contain -o option
                            # but instead contain -MT "file.o file.d" -MF file.d
                            if opt == "-MT" or opt == "-MF":
                                subopts = val.split(" ")
                                for subopt in subopts:
                                    if re.search(r"\.o$", subopt):
                                        cmd["out"] = subopt
                                skip_next_opt = True
                            # Output file.
                            elif opt == "-o":
                                cmd["out"] = val
                            else:
                                # Use original formatting of options.
                                if skip_next_opt:
                                    cmd["opts"].extend(["{}".format(opt), val])
                                else:
                                    cmd["opts"].append("{}{}{}".format(opt, eq, val))

                            break

                    if not match:
                        # Options without values
                        if re.search(r"^-.+$", opt):
                            cmd["opts"].append(opt)
                        # Input files.
                        else:
                            cmd["in"].append(opt)
            elif cmd["type"] == "mv":
                # We assume that 'MV' options always have such the form:
                #     [-opt]... in_file out_file
                for opt in opts:
                    if re.search(r"^-", opt):
                        cmd["opts"].append(opt)
                    elif not cmd["in"]:
                        cmd["in"].append(opt)
                    else:
                        cmd["out"] = opt
            elif cmd["type"] == "ar":
                # We assume that ar options always have such the form:
                #     opts out_file in_file
                cmd["type"] = "ld"

                for opt in opts:
                    if cmd["opts"] == []:
                        cmd["opts"].append(opt)
                    elif not cmd["out"]:
                        cmd["out"] = opt
                    else:
                        cmd["in"].append(opt)
            elif cmd["type"] == "objcopy":
                # Support for objcopy is in alpha stage
                cmd["type"] = "ld"
                skip_next_opt = False

                for index, opt in enumerate(opts):
                    if skip_next_opt:
                        skip_next_opt = False
                        continue

                    # TODO: --output-target=bfdname
                    if re.search(r"^-", opt) and opt != "-O":
                        cmd["opts"].append(opt)
                    elif opt == "-O":
                        cmd["out"] = opts[index + 1]
                        skip_next_opt = True
                    else:
                        cmd["in"].append(opt)
            else:
                raise NotImplementedError(
                    "Build command '{}' is not supported yet".format(cmd["type"]))

            # if in_files_are_required and not cmd["in"]:
            #     raise ValueError("Could not get raw build command input files" +
            #                      " from options '{}'".format(opts))
                # TODO: Fix - gcc test.c
            # if out_file_is_required and not cmd["out"]:
            #     raise ValueError("Could not get raw build command output file" +
            #                      " from options "{0}"".format(opts))

            # Check thar all original options becomes either input files or output file or options.
            # Option -o isn"t included in the resulting set.
            # original_opts = opts
            # for unwanted_opt in ["-o", "-O", "-MT", "-MF"]:
            #     if unwanted_opt in original_opts:
            #         original_opts.remove(unwanted_opt)
            # resulting_opts = cmd["in"] + cmd["opts"]
            # if cmd["out"]:
            #     resulting_opts.append(cmd["out"])
            # if set(original_opts) != set(resulting_opts):
            #     raise RuntimeError("Some options were not parsed: '{} != {} + {} + {}''".format(
            #                        original_opts, cmd["in"], cmd["out"], cmd["opts"]))

            cmds["build commands"].append(cmd)


def generate_final_cmds():
    replace = dict()
    dev_null = dict()

    final_cmds["src"] = cmds["src"]
    final_cmds["build commands"] = []

    for cmd in cmds["build commands"]:
        if cmd["type"] == "mv":
            for element in cmd["in"]:
                replace[element] = cmd["out"]

    for cmd in cmds["build commands"]:
        if cmd["type"] != "mv":
            bad = False
            for element in cmd["in"]:
                if element == "-" or element == "/dev/null":
                    bad = True
                    dev_null[cmd["out"]] = 1
                elif element in dev_null:
                    bad = True
                elif re.search(r"\.(s|S)$", element):
                    if cmd["type"] == "cc":
                        cmd["type"] = "asm"
                elif re.search(r"\.l?o$", element):
                    cmd["type"] = "ld"
            if cmd["in"] == []:
                bad = True
                dev_null[cmd["out"]] = 1

            if bad is True:
                continue

            for element in cmd["in"]:
                if not re.search(r"\.mod\.o", element):
                    if element in replace:
                        cmd["in"].remove(element)
                        cmd["in"].append(replace[element])
            if cmd["out"] is not None:
                if cmd["out"] in replace:
                    cmd["out"] = replace[cmd["out"]]
            elif cmd["type"] == "cc":
                cmd["out"] = os.path.dirname(cmd["in"][0]) + "/a.out"

            final_cmds["build commands"].append(cmd)


def dump_cmds():
    with open(json_cmds, "w") as cmd_fh:
        json.dump(final_cmds, cmd_fh, sort_keys=True, indent=4)


def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:
        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
            raise  # re-raise exception if a different error occurred


def handler(signum, frame):
    print('Signal handler called with signal', signum)

    remove_stubs(args.stubs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", metavar="PATH", help="set PATH to sources", required=True)
    parser.add_argument("--make", metavar="COMMAND", help="replace default 'make' command by COMMAND", required=False, default="make -j" + str(processes))
    parser.add_argument("--keep", help="keep {} file".format(os.path.basename(raw_cmds)), required=False, action="store_true")
    parser.add_argument("--stubs", metavar="PATHs", help="list of PATHs where stubs will be stored", required=False, nargs='+', default=[])
    args = parser.parse_args()

    check_arguments(args)
    parse_config()

    src = os.path.abspath(args.sources)
    args.stubs.insert(0, realdir)

    signal.signal(signal.SIGINT, handler)

    build_src(src)

    if os.path.exists(raw_cmds):
        process_raw_cmds(src)
        generate_final_cmds()
        dump_cmds()

        if not args.keep:
            silentremove(raw_cmds)

        print("Complete")
    else:
        sys.exit("Something went wrong - build commands were not extracted")
