# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 ISPRAS (http://www.ispras.ru)
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
import collections
import json
import os
import re
import sys
import subprocess

# All generated files will be stored in working directory
WORKDIR = os.getcwd() + "/workdir"
# Path to aspect file containing info requests to source files
ASPECT = WORKDIR + "/info.aspect"
# Path to file containing information about function calls by pointer
CALLP = WORKDIR + "/callp.txt"
# Linux only: Path to file containing information about exported functions
EXPORTED = WORKDIR + "/exported.txt"
# Path to file containing information about macro functions
DEFINE = WORKDIR + "/define.txt"
# Path to CIF working directory
CIFDIR = WORKDIR + "/cif/"
# Path to file containing information from compilation of .c files
OF = WORKDIR + "/object_files.txt"
# Path to file containing CIF error log
CIF_ERR_LOG = WORKDIR + "/cif_err_log.txt"
# Path to file containing Kartograpger error log
ERR_LOG = WORKDIR + "/err_log.txt"

EXE_FILES = []
CALL_FILES = []
DECL_FILES = []
CIF_OUTPUT = []


def nested_dict():
    return collections.defaultdict(nested_dict)
KM = nested_dict()


def gen_info_requests():
    """
    Generates special aspect file with information reqests.

    This file is used by CIF to obtain the following information:
        - for each function call:
            - path to the file containing the call ($func_context_path)
            - name of the function containing the call (context function, $func_context_name)
            - number of the line with context function definition ($func_context_decl_line)
            - number of the line with the call ($call_line)
            - name of the function ($func_name)
            - number of the line with the declaration of the called function ($decl_line)
        - for each function definition:
            - path to the file containing the definition ($path)
            - number of the line with the definition ($decl_line)
            - name of the function ($func_name)
            - signature of the function ($signature)
        - for each compilation command:
            - name of the object file ($env<CC>)
            - list of the source files (.c and .h files) that will be compiled ($path)
        - for each function call by pointer:
            - path to the file containing the call ($func_context_path)
            - name of the function containing the call (context function, $func_context_name)
            - number of the line with context function definition ($func_context_decl_line)
            - number of the line with the call ($call_line)
            - name of the function pointer ($func_ptr_name)
        - for each macro function:
            - path to the file containing the macro ($path)
            - name of the macro ($macro_name)

    For the Linux kernel it will additionally do the following:
        - remove likely(x) and unlikely(x) macro functions from sources
        - retreave the list of exported functions

    """

    print("Generating aspect file with info requests")

    inforequest_types = ["execution", "call", "declare_func"]
    function_types = ["static", ""]

    with open(ASPECT, "w") as aspect_fh:
        aspect_fh.write("around: define(likely(x)) { (x) }\n\n")
        aspect_fh.write("around: define(unlikely(x)) { (x) }\n\n")

        for inforequest_type in inforequest_types:
            for function_type in function_types:
                if function_type == "":
                    file_name = "{}/{}.txt".format(WORKDIR, inforequest_type)
                else:
                    file_name = "{}/{}-{}.txt".format(WORKDIR, function_type, inforequest_type)

                aspect_fh.write("info: {}({} $ $(..)) {{\n".format(inforequest_type, function_type))

                if inforequest_type == "execution":
                    aspect_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<CC>>\n".format(OF))
                    aspect_fh.write("  $fprintf<\"{}\",\"%s %s %s %s\\n\",$path,$decl_line,$func_name,$signature>\n".format(file_name))
                    EXE_FILES.append(file_name)
                elif inforequest_type == "call":
                    aspect_fh.write("  $fprintf<\"{}\",\"%s %s %s %s %s %s\\n\",$func_context_path,$func_context_name,$func_context_decl_line,$call_line,$func_name,$decl_line>\n".format(file_name))
                    CALL_FILES.append(file_name)
                elif inforequest_type == "declare_func":
                    aspect_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<CC>>\n".format(OF))
                    aspect_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$func_name>\n".format(file_name))
                    DECL_FILES.append(file_name)

                aspect_fh.write("}\n\n")
                CIF_OUTPUT.append(file_name)

        aspect_fh.write("info: callp($ $(..)) {\n")
        aspect_fh.write("  $fprintf<\"{}\",\"%s %s %s %s %s\\n\",$func_context_path,$func_context_name,$func_context_decl_line,$call_line,$func_ptr_name>\n".format(CALLP))
        aspect_fh.write("}\n\n")

        aspect_fh.write("info: expand(__EXPORT_SYMBOL(sym, sec)) {\n")
        aspect_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$arg_val1>\n".format(EXPORTED))
        aspect_fh.write("}\n\n")

        for args in ["arg1", "arg1, arg2", "arg1, arg2, arg3"]:
            aspect_fh.write("info: define($({})) {{\n".format(args))
            aspect_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$macro_name>\n".format(DEFINE))
            aspect_fh.write("}\n\n")

        CIF_OUTPUT.append(EXPORTED)
        CIF_OUTPUT.append(DEFINE)
        CIF_OUTPUT.append(CALLP)
        CIF_OUTPUT.append(OF)


def process_bc(bc, cif):
    print("Processing build commands")

    current_command = 0
    number_of_commands = 0
    src = ""

    with open(bc, "r") as bc_fh:
        bc_json = json.load(bc_fh)

        if "source tree root" not in bc_json:
            sys.exit("Can't find path to source tree root")
        elif "build commands" not in bc_json:
            sys.exit("Can't find build commands")

        src = bc_json["source tree root"]
        if not os.path.isdir(src):
            sys.exit("Specified path to source tree root is not valid")

        number_of_commands = len(bc_json["build commands"])
        if number_of_commands == 0:
            sys.exit("Specified json file doesn't contain valid CC or LD commands")

        for command in bc_json["build commands"]:
            current_command += 1

            if "type" not in command:
                sys.exit("Can't find 'type' field in the next build command: {}".format(command))
            elif "in files" not in command:
                sys.exit("Can't find 'in files' field in build command: {}".format(command))
            elif "out file" not in command:
                sys.exit("Can't find 'out file' field in build command: {}".format(command))

            if command["type"] == "CC":
                process_cc_cmd(command, src, cif)
            elif command["type"] == "LD":
                process_ld_cmd(command)

            sys.stdout.write("\r{} of {} commands processed".format(current_command, number_of_commands))
        sys.stdout.write("\n")

        return src


def process_cc_cmd(command, src, cif):
    # Temporary workaround
    if command["in files"] == [] or command["in files"][0] == "-" or command["in files"][0] == "/dev/null" or command["in files"][0] is None or re.search(r'\.(s|S)$', command["in files"][0]) or re.search(r'\.o$', command["in files"][0]):
        return
    if command["out file"] is None:
        return

    cif_in = command["in files"][0]
    cif_out = CIFDIR + "/" + command["out file"] + "/" + os.path.basename(command["out file"])

    if re.search(r'(/purgatory/)|(/boot/)', cif_in):
        # TODO: Investigate this issue
        return

    cif_out = os.path.normpath(cif_out)
    cif_in = os.path.normpath(cif_in)

    if not os.path.isdir(cif_out):
        try:
            os.makedirs(os.path.dirname(cif_out))
        except OSError as e:
            if e.errno != 17:
                raise

    os.chdir(src)

    os.environ['CC'] = command["out file"]

    cif_args = [cif,
                "--debug", "ALL",
                "--in", cif_in,
                "--aspect", ASPECT,
                "--back-end", "src",
                "--stage", "instrumentation",
                "--out", cif_out]

    cif_args.append("--")

    cif_opts = []
    cif_opts.append("-iquote{}".format(os.path.dirname(cif_in)))
    cif_opts.extend(command["opts"])

    for opt in cif_opts:
        # Related with old GCC (Aspectator) bugs.
        if opt == "-Wno-maybe-uninitialized":
            continue
        elif opt == "--param=allow-store-data-races=0":
            continue
        elif re.match(r'-mpreferred-stack-boundary', opt):
            continue
        elif opt == "-fsanitize=kernel-address":
            continue
        elif opt == "-Werror=date-time":
            continue
        elif opt == "-Werror-implicit-function-declaration":
            continue
        elif opt == "-m16":
            continue

        cif_opt = re.sub(r'\"', r'\\"', opt)
        cif_args.append("\'{}\'".format(cif_opt))

    cif_log = os.path.dirname(cif_out) + "/cif_log.txt"
    cif_args.extend([">", cif_log, '2>&1'])

    cif_args_str = ' '.join(cif_args)

    if os.system(cif_args_str):
        dump_error_information(cif_args_str, cif_log)

    os.chdir(WORKDIR)


def dump_error_information(args, log):
    with open(log, "r") as log_fh:
        log_str = log_fh.readlines()

    with open(CIF_ERR_LOG, "a") as log_fh:
        log_fh.write("CIF ARGUMENTS: " + args + "\n\n")
        log_fh.write("CIF LOG: ")
        log_fh.writelines(log_str)
        log_fh.write("\n\n")


def process_ld_cmd(command):
    out = os.path.normpath(command["out file"])

    for in_file in command["in files"]:
        in_file_n = os.path.normpath(in_file)

        KM["object files"][out]["linked from"][in_file_n] = 1
        KM["object files"][in_file_n]["linked to"][out] = 1


def normalize_cif_output(src):
    print("Normalizing CIF output")

    for output_file in CIF_OUTPUT:
        if (not os.path.isfile(output_file)):
            print("Couldn't find '{}'".format(output_file))
            continue

        with open(output_file, "r") as output_fh:
            with open(output_file + ".temp", "w") as temp_fh:
                for line in output_fh:
                    m = re.match(r'(\S*) (.*)', line)

                    if m:
                        path = m.group(1)
                        rest = m.group(2)

                        path = os.path.normpath(path)
                        path = re.sub(src + "/", "", path)

                        temp_fh.write("{} {}\n".format(path, rest))

        os.remove(output_file)
        os.rename(output_file + ".temp", output_file)


def remove_duplicate_lines():
    print("Removing duplicate lines in CIF output")

    for output_file in CIF_OUTPUT:
        if (not os.path.isfile(output_file)):
            continue

        dup_lines = dict()

        with open(output_file, "r") as output_fh:
            with open(output_file + ".temp", "w") as temp_fh:
                for line in output_fh:
                    if line not in dup_lines:
                        temp_fh.write(line)
                        dup_lines[line] = 1

        os.remove(output_file)
        os.rename(output_file + ".temp", output_file)


def process_of():
    print("Processing translation units")
    with open(OF, "r") as of_fh:
        for line in of_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                source_file = m.group(1)
                object_file = m.group(2)

                KM["source files"][source_file]["compiled to"][object_file] = 1
                KM["object files"][object_file]["compiled from"][source_file] = 1


def process_ld():
    print("Processing link commands")

    for source_file in KM["source files"]:
        for object_file in KM["source files"][source_file]["compiled to"]:
            viewed_object_files = dict()
            process_ld_recursive(source_file, object_file, viewed_object_files)


def process_ld_recursive(source_file, object_file, viewed_object_files):
    if "linked to" not in KM["object files"][object_file]:
        return
    elif object_file in viewed_object_files:
        return

    viewed_object_files[object_file] = 1

    for linked_to in KM["object files"][object_file]["linked to"]:
        KM["source files"][source_file]["used in"][linked_to] = 1
        process_ld_recursive(source_file, linked_to, viewed_object_files)


def process_exe():
    print("Processing definitions")
    for exe_file in EXE_FILES:
        if not os.path.isfile(exe_file):
            continue

        with open(exe_file, "r") as exe_fh:
            for line in exe_fh:
                m = re.match(r'(\S*) (\S*) (\S*) (.*)', line)
                if m:
                    src_file = m.group(1)
                    decl_line = m.group(2)
                    func = m.group(3)
                    func_signature = m.group(4)
                    func_type = "ordinary"

                    if re.search(r'static', exe_file):
                        func_type = "static"

                    if func in KM["functions"] and src_file in KM["functions"][func]:
                        kmg_error("Function '{}' is defined more than once in '{}'".format(func, src_file))
                        continue

                    KM["functions"][func][src_file]["type"] = func_type
                    KM["functions"][func][src_file]["signature"] = func_signature
                    KM["functions"][func][src_file]["decl line"] = decl_line


def process_exp():
    # Linux kernel only
    if not os.path.isfile(EXPORTED):
        return
    print("Processing exported functions")

    with open(EXPORTED, "r") as exp_fh:
        for line in exp_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                src_file = m.group(1)
                func = m.group(2)

                # Variables can also be exported
                if func not in KM["functions"]:
                    continue
                elif src_file not in KM["functions"][func]:
                    continue

                KM["functions"][func][src_file]["type"] = "exported"


def process_def():
    if not os.path.isfile(DEFINE):
        return
    print("Processing macro functions")

    with open(DEFINE, "r") as def_fh:
        for line in def_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                src_file = m.group(1)
                macro = m.group(2)

                KM["macro"][macro][src_file] = 1


def process_decl():
    print("Processing declarations")
    for decl_file in DECL_FILES:
        if not os.path.isfile(decl_file):
            continue

        with open(decl_file, "r") as decl_fh:
            for line in decl_fh:
                m = re.match(r'(\S*) (\S*)', line)
                if m:
                    decl_file = m.group(1)
                    decl_name = m.group(2)

                    if decl_name not in KM["functions"]:
                        continue

                    decl_type = "ordinary"
                    if re.search(r'static', decl_file):
                        decl_type = "static"

                    for src_file in KM["functions"][decl_name]:
                        decl_line = KM["functions"][decl_name][src_file]["decl line"]

                        if ((KM["functions"][decl_name][src_file]["type"] == decl_type) or
                           (KM["functions"][decl_name][src_file]["type"] == "exported")):
                            if src_file == decl_file:
                                KM["functions"][decl_name][src_file]["declared in"][decl_file] = 1
                            elif list(set(KM["source files"][src_file]["compiled to"]) &
                                      set(KM["source files"][decl_file]["compiled to"])):
                                KM["functions"][decl_name][src_file]["declared in"][decl_file] = 1


def build_km():
    print("Building KM")

    global call_type
    global context_file
    global context_func
    global context_decl_line
    global call_line
    global func
    global call_decl_line

    for call_file in CALL_FILES:
        if not os.path.isfile(call_file):
            continue

        with open(call_file, "r") as call_fh:
            call_type = "ordinary"
            if re.search(r'static', call_file):
                call_type = "static"

            for line in call_fh:
                m = re.match(r'(\S*) (\S*) (\S*) (\S*) (\S*) (\S*)', line)
                if m:

                    context_file = m.group(1)
                    context_func = m.group(2)
                    context_decl_line = m.group(3)
                    call_line = m.group(4)
                    func = m.group(5)
                    call_decl_line = m.group(6)

                    match_call_and_def()

    reverse_km()
    process_callp()
    clean_kmg_err()


def reverse_km():
    for func in KM["functions"]:
        for src_file in KM["functions"][func]:
            for context_func in KM["functions"][func][src_file]["called in"]:
                for context_file in KM["functions"][func][src_file]["called in"][context_func]:
                    KM["functions"][context_func][context_file]["calls"][func][src_file] = KM["functions"][func][src_file]["called in"][context_func][context_file]


def process_callp():
    if not os.path.isfile(CALLP):
        return

    with open(CALLP, "r") as callp_fh:
        for line in callp_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*) (\S*)', line)
            if m:
                context_file = m.group(1)
                context_func = m.group(2)
                context_decl_line = m.group(3)
                call_line = m.group(4)
                func_ptr = m.group(5)

                KM["functions"][context_func][context_file]["calls by pointer"][func_ptr][call_line] = 1


def match_call_and_def():
    # Some Linux workarounds
    if re.match(r'(__builtin)|(__compiletime)', func):
        return
    if re.match(r'__bad', func) and func not in KM["functions"]:
        return

    if func not in KM["functions"]:
        KM["functions"][func]["unknown"]["decl line"] = "unknown"
        KM["functions"][func]["unknown"]["type"] = call_type
        KM["functions"][func]["unknown"]["called in"][context_func][context_file][call_line] = 1

        kmg_error("NO_DEFS_IN_KM: {}".format(func))

        return

    possible_src = []
    for src_file in KM["functions"][func]:
        if src_file == "unknown":
            continue
        elif (KM["functions"][func][src_file]["type"] == call_type or
              KM["functions"][func][src_file]["type"] == "exported"):
            possible_src.append(src_file)

    if len(possible_src) == 0:
        KM["functions"][func]["unknown"]["decl line"] = "unknown"
        KM["functions"][func]["unknown"]["type"] = call_type
        KM["functions"][func]["unknown"]["called in"][context_func][context_file][call_line] = 0

        # It will be a generator's fault until it supports aliases
        if not re.match(r'__mem', func):
            kmg_error("NO_POSSIBLE_DEFS: {}".format(func))

    elif len(possible_src) == 1:
        src_file = possible_src[0]
        KM["functions"][func][src_file]["called in"][context_func][context_file][call_line] = 7

    else:
        found_src = [None] * 7
        for x in range(0, len(found_src)):
            found_src[x] = []

        for src_file in possible_src:
            if KM["functions"][func][src_file]["type"] == "exported":
                found_src[1].append(src_file)
                continue

            decl_line = KM["functions"][func][src_file]["decl line"]

            if src_file == context_file:
                found_src[6].append(src_file)
            elif (call_decl_line == decl_line and
                  list(set(KM["source files"][src_file]["compiled to"]) &
                       set(KM["source files"][context_file]["compiled to"]))):
                found_src[5].append(src_file)
            elif (list(set(KM["source files"][src_file]["compiled to"]) &
                       set(KM["source files"][context_file]["compiled to"]))):
                found_src[4].append(src_file)
            elif (call_type == "ordinary" and
                  ("used in" in KM["source files"][src_file] and
                   "used in" in KM["source files"][context_file] and
                   list(set(KM["source files"][src_file]["used in"]) &
                        set(KM["source files"][context_file]["used in"])))):
                found_src[3].append(src_file)
            elif call_type == "ordinary":
                for decl_file in KM["functions"][func][src_file]["declared in"]:
                    if list(set(KM["source files"][decl_file]["compiled to"]) &
                            set(KM["source files"][context_file]["compiled to"])):
                        found_src[2].append(src_file)
                        break

        found_src[0].append("unknown")

        for x in range(len(found_src) - 1, -1, -1):
            if found_src[x] != []:
                if len(found_src[x]) > 1:
                    kmg_error("MULTIPLE_MATCHES: {} call in {}".format(func, context_file))
                for src_file in found_src[x]:
                    KM["functions"][func][src_file]["called in"][context_func][context_file][call_line] = x

                    if src_file == "unknown":
                        KM["functions"][func][src_file]["decl line"] = "unknown"
                        KM["functions"][func][src_file]["type"] = call_type

                        kmg_error("CANT_MATCH_DEF: {} call in {}".format(func, context_file))
                break


def kmg_error(str):
    """
    Prints to ERR_LOG file an error message related to work of the generator itself.
    """

    with open(ERR_LOG, "a") as err_fh:
        err_fh.write("{}\n".format(str))


def clean_kmg_err():
    """
    Removes duplicate error messages in ERR_LOG file.
    """

    if (not os.path.isfile(ERR_LOG)):
            return

    dup_lines = dict()

    with open(ERR_LOG, "r") as output_fh:
        with open(ERR_LOG + ".temp", "w") as temp_fh:
            for line in output_fh:
                if line not in dup_lines:
                    temp_fh.write(line)
                    dup_lines[line] = 1

    os.remove(ERR_LOG)
    os.rename(ERR_LOG + ".temp", ERR_LOG)


def store_km():
    """
    Serializes generated model in a form of JSON.
    """

    print("Serializing generated model")
    with open(WORKDIR + "/km.json", "w") as km_fh:
        json.dump(KM, km_fh)

if __name__ == "__main__":
    # Parsing of command line options.
    parser = argparse.ArgumentParser()
    parser.add_argument('--bc', metavar='PATH', help='set PATH to json with build commands', required=True)
    parser.add_argument('--cif', metavar='PATH', help='set PATH to CIF executable', default="cif")
    options = parser.parse_args()

    # Only --bc option is required - it specifies path to json file that contains linking and compilation commands (build commands, bc) of analysed project.
    # --cif option is not required, but in this case path to cif should be located in $PATH

    if not os.path.isfile(options.bc):
        sys.exit("{} is not a file".format(options.bc))

    try:
        proc = subprocess.Popen([options.cif], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = proc.communicate()
    except FileNotFoundError as e:
        if e.errno != 2:
            raise
        sys.exit("You should specify --cif option")

    if os.path.isdir(WORKDIR):
        sys.exit("Working directory {} already exists. Please delete or backup it and relunch the script".format(WORKDIR))
    else:
        os.mkdir(WORKDIR)

    gen_info_requests()
    src = process_bc(options.bc, options.cif)

    normalize_cif_output(src)
    remove_duplicate_lines()

    process_of()
    process_ld()
    process_exe()
    process_exp()
    process_def()
    process_decl()

    build_km()
    store_km()
    print("Complete")
