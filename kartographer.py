# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 ISPRAS (http://www.ispras.ru)
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
import subprocess
import sys

WD = os.getcwd() + "/workdir"  # A place for all generated files

# The following files will contain information about source code and will be created by CIF
EXECUTION = WD + "/execution.txt"  # Info about function definitions
CALL = WD + "/call.txt"  # Info about function calls
DECL = WD + "/declare_func.txt"  # Info about function declarations
CALLP = WD + "/callp.txt"  # Info about function calls via a function pointer
USE_FUNC = WD + "/use_func.txt"  # Info about using function names in pointers (in function context only)
USE_VAR = WD + "/use_var.txt"  # Info about using global variables in function context
INIT_GLOBAL = WD + "/init_global.txt"  # Info about init values of global variables
DEFINE = WD + "/define.txt"  # Info about macro functions
OF = WD + "/object_files.txt"  # Info about from compilation of .c files
EXPORTED = WD + "/exported.txt"  # Info about exported functions (Linux kernel only)
INIT = WD + "/init.txt"  # Info about module_init functions (Linux kernel only)
EXIT = WD + "/exit.txt"  # Info about module_exit functions (Linux kernel only)

FILES = [EXECUTION, CALL, DECL, CALLP, USE_FUNC, USE_VAR, INIT_GLOBAL, DEFINE, OF, EXPORTED, INIT, EXIT]

# Log files
CIF_ERR_LOG = WD + "/cif_err.log"  # Path to file containing CIF error log
ERR_LOG = WD + "/err.log"  # Path to file containing Kartograpger error log


def nested_dict():
    return collections.defaultdict(nested_dict)
KM = nested_dict()


def gen_info_requests():
    """
    Generates special aspect file with information reqests.

    This file is used by CIF to obtain the following information:
        - for each function definition (info: execution):
            - path of the current source file ($path)
            - function name ($func_name)
            - definition line number ($decl_line)
        - for each function declaration (info: declare_func):
            - path of the current source file ($path)
            - function name ($func_name)
            - declaration line number ($decl_line)
        - for each function call (info: call):
            - path of the current source file ($func_context_path)
            - name of the function that contains the call (context function, $func_context_name)
            - function name ($func_name)
            - call line number ($call_line)
            - called function declaration line number ($decl_line)
        - for each compilation command:
            - name of the object file ($env<OBJ>)
            - list of the source files (.c and .h files) that will be compiled ($path)
        - for each function call by pointer (info: callp):
            - path of the current source file ($func_context_path)
            - name of the function that contains the call(context function, $func_context_name)
            - function pointer name ($func_ptr_name)
            - call line number ($call_line)
        - for each function name use in function pointers (info: use_func):
            - path of the current source file ($func_context_path)
            - name of the function that uses the function name ($func_context_name)
            - function name ($func_name)
            - use line number ($use_line)
        - for each global variable use in function context (info: use_var):
            - path of the current source file ($func_context_path)
            - name of the function that uses the global variable ($func_context_name)
            - variable name ($var_name)
            - use line number ($use_line)
        - for each global variable initialization (info: init_global):
            - path of the current source file ($path)
            - variable name ($var_name)
            - preformatted list of init values ($fprintf_var_init_values)
        - for each macro and macro function:
            - path of the current source file ($path)
            - number of the line with macro definition ($line)
            - name of the macro ($macro_name)

    For the Linux kernel it will additionally do the following:
        - remove likely(x) and unlikely(x) macro functions from sources
        - retreave the list of exported functions
        - retreave the list of module_init functions
        - retreave the list of module_exit functions

    """

    print("Generating aspect file with info requests")

    # Path to aspect file containing info requests to source files
    aspect = WD + "/info.aspect"

    with open(aspect, "w") as asp_fh:
        asp_fh.write("around: define(likely(x)) { (x) }\n\n")  # Workaround for CIF
        asp_fh.write("around: define(unlikely(x)) { (x) }\n\n")

        asp_fh.write("info: execution(static $ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<OBJ>>\n".format(OF))
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s static\\n\",$path,$func_name,$decl_line>\n".format(EXECUTION))
        asp_fh.write("}\n\n")

        asp_fh.write("info: execution($ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<OBJ>>\n".format(OF))
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s global\\n\",$path,$func_name,$decl_line>\n".format(EXECUTION))
        asp_fh.write("}\n\n")

        asp_fh.write("info: declare_func($ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<OBJ>>\n".format(OF))
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s\\n\",$path,$func_name,$decl_line>\n".format(DECL))
        asp_fh.write("}\n\n")

        asp_fh.write("info: call(static $ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s %s static\\n\",$func_context_path,$func_context_name,$func_name,$call_line>\n".format(CALL))
        asp_fh.write("}\n\n")

        asp_fh.write("info: call($ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s %s global\\n\",$func_context_path,$func_context_name,$func_name,$call_line>\n".format(CALL))
        asp_fh.write("}\n\n")

        asp_fh.write("info: callp($ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s %s\\n\",$func_context_path,$func_context_name,$func_ptr_name,$call_line>\n".format(CALLP))
        asp_fh.write("}\n\n")

        asp_fh.write("info: use_func($ $(..)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s %s\\n\",$func_context_path,$func_context_name,$func_name,$use_line>\n".format(USE_FUNC))
        asp_fh.write("}\n\n")

        asp_fh.write("info: use_var($ $) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s %s\\n\",$func_context_path,$func_context_name,$var_name,$use_line>\n".format(USE_VAR))
        asp_fh.write("}\n\n")

        asp_fh.write("info: init_global($ $) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$env<OBJ>>\n".format(OF))
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\",$path,$var_name>\n".format(INIT_GLOBAL))
        asp_fh.write("  $fprintf_var_init_values<\"{}\">\n".format(INIT_GLOBAL))
        asp_fh.write("  $fprintf<\"{}\",\"\\n\">\n".format(INIT_GLOBAL))
        asp_fh.write("}\n\n")

        asp_fh.write("info: expand(__EXPORT_SYMBOL(sym, sec)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$arg_val1>\n".format(EXPORTED))
        asp_fh.write("}\n\n")

        asp_fh.write("info: expand(module_init(x)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$arg_val1>\n".format(INIT))
        asp_fh.write("}\n\n")

        asp_fh.write("info: expand(module_exit(x)) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s\\n\",$path,$arg_val1>\n".format(EXIT))
        asp_fh.write("}\n\n")

        asp_fh.write("info: define($) {\n")
        asp_fh.write("  $fprintf<\"{}\",\"%s %s %s\\n\",$path,$macro_name,$line>\n".format(DEFINE))
        asp_fh.write("}\n\n")

        # Currently there is no way to find macro functions without specifying exact number of arguments: one argument (arg1), two arguments (arg1, arg2), and so on (CIF issue)
        for args in ["arg1", "arg1, arg2", "arg1, arg2, arg3"]:
            asp_fh.write("info: define($({})) {{\n".format(args))
            asp_fh.write("  $fprintf<\"{}\",\"%s %s %s\\n\",$path,$macro_name,$line>\n".format(DEFINE))
            asp_fh.write("}\n\n")

    return aspect


def process_build_commands(bc, cif, aspect):
    print("Processing build commands")

    with open(bc, "r") as bc_fh:
        bc_json = json.load(bc_fh)

        # json must be valid
        if "src" not in bc_json:
            sys.exit("Can't find path to source tree root in bc json")
        elif "build commands" not in bc_json:
            sys.exit("Can't find build commands in bc json")
        elif not os.path.isdir(bc_json["src"]):
            sys.exit("Specified path to source tree root is not valid")

        src = os.path.abspath(bc_json["src"])

        number_of_commands = len(bc_json["build commands"])
        if number_of_commands == 0:
            sys.exit("Specified json file doesn't contain valid gcc or ld commands")
        curr_number = 0

        for command in bc_json["build commands"]:
            curr_number += 1

            if "type" not in command:
                sys.exit("Can't find 'type' field in the next build command: {}".format(command))
            elif "in" not in command:
                sys.exit("Can't find 'in' field in build command: {}".format(command))
            elif "out" not in command:
                sys.exit("Can't find 'out' field in build command: {}".format(command))

            if command["type"] == "gcc":
                process_cc_command(command, src, cif, aspect)
            elif command["type"] == "ld":
                process_ld_command(command, src)

            sys.stdout.write("\r{} of {} commands processed".format(curr_number, number_of_commands))
        sys.stdout.write("\n")

        os.chdir(os.getcwd())

    return src


def process_cc_command(command, src, cif, aspect):
    # Workarounds for bad cc commands
    if command["in"] == []:
        return
    elif command["out"] is None:
        return

    cif_in = command["in"][0]

    if cif_in == "-" or cif_in == "/dev/null" or cif_in is None:
        return
    elif re.search(r'\.(s|S)$', cif_in) or re.search(r'\.o$', cif_in) or re.search(r'conftest.c', cif_in):
        return

    if re.search(r'(/purgatory/)|(/boot/)', cif_in):
        # TODO: Investigate this issue
        return

    if "cwd" in command:
        os.chdir(command["cwd"])
    else:
        os.chdir(src)

    cif_in = os.path.abspath(cif_in)

    cif_out = os.path.join(os.path.abspath(command["out"]), os.path.basename(command["out"]))
    cif_out = os.path.normpath(os.path.join(WD + "/cif/", os.path.relpath(cif_out, start=src)))

    if not os.path.isdir(cif_out):
        try:
            os.makedirs(os.path.dirname(cif_out))
        except OSError as e:
            if e.errno != 17:
                raise

    os.environ['OBJ'] = command["out"]

    cif_args = [cif,
                "--debug", "ALL",
                "--in", cif_in,
                "--aspect", aspect,
                "--back-end", "src",
                "--stage", "instrumentation",
                "--out", cif_out]

    cif_args.append("--")
    cif_args.append("-iquote{}".format(os.path.dirname(cif_in)))

    for opt in command["opts"]:
        # Aspectator is based on GCC 4.6 which doesn't support some options
        if opt == "-Wno-maybfe-uninitialized":
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

        m = re.search(r'-I(.*)', opt)
        if m:
            opt = "-I" + os.path.abspath(m.group(1))

        cif_opt = re.sub(r'\"', r'\\"', opt)
        cif_args.append("\'{}\'".format(cif_opt))

    cif_log = os.path.dirname(cif_out) + "/cif_log.txt"
    cif_args.extend([">", cif_log, '2>&1'])

    cif_args_str = ' '.join(cif_args)
    if subprocess.call(cif_args_str, shell=True):
        store_error_information(cif_args_str, cif_log)

    # Add gathered information to KM
    rel_in = os.path.relpath(command["in"][0], start=src)
    rel_out = os.path.relpath(command["out"], start=src)
    KM["source files"][rel_in]["compiled to"][rel_out] = 1
    KM["object files"][rel_out]["compiled from"][rel_in] = 1

    os.chdir(src)


def store_error_information(args, log):
    with open(log, "r") as log_fh:
        log_str = log_fh.readlines()

    with open(CIF_ERR_LOG, "a") as log_fh:
        log_fh.write("CIF ARGUMENTS: " + args + "\n\n")
        log_fh.write("CIF LOG: ")
        log_fh.writelines(log_str)
        log_fh.write("\n\n")


def process_ld_command(command, src):
    if command["out"] == None:
        out = "unknown"
    else:
        out = command["out"]

    for in_file in command["in"]:
        KM["object files"][out]["linked from"][in_file] = 1
        KM["object files"][in_file]["linked to"][out] = 1


def normalize_cif_output(src):
    print("Normalizing CIF output")

    for file in FILES:
        if (not os.path.isfile(file)):
            print("Couldn't find '{}'".format(file))
            continue

        seen = set()

        with open(file, "r") as fh:
            with open(file + ".temp", "w") as temp_fh:
                for line in fh:
                    if line not in seen:
                        seen.add(line)
                        m = re.match(r'(\S*) (.*)', line)

                        if m:
                            path = m.group(1)
                            rest = m.group(2)

                            path = os.path.normpath(path)
                            if os.path.isabs(path):
                                path = os.path.relpath(path, start=src)

                            if file == OF:
                                rest = os.path.normpath(rest)
                                if os.path.isabs(rest):
                                    rest = os.path.relpath(rest, start=src)

                            temp_fh.write("{} {}\n".format(path, rest))

        os.remove(file)
        os.rename(file + ".temp", file)


def process_of():
    print("Identification relationship between object and source files")

    with open(OF, "r") as of_fh:
        for line in of_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                source_file = m.group(1)
                object_file = m.group(2)

                KM["source files"][source_file]["compiled to"][object_file] = 1
                KM["object files"][object_file]["compiled from"][source_file] = 1

    for source_file in KM["source files"]:
        for object_file in KM["source files"][source_file]["compiled to"]:
            viewed_object_files = dict()
            process_of_recursive(source_file, object_file, viewed_object_files)


def process_of_recursive(source_file, object_file, viewed_object_files):
    if "linked to" not in KM["object files"][object_file]:
        return
    elif object_file in viewed_object_files:
        return

    viewed_object_files[object_file] = 1

    for linked_to in KM["object files"][object_file]["linked to"]:
        KM["source files"][source_file]["used in"][linked_to] = 1
        process_of_recursive(source_file, linked_to, viewed_object_files)


def process_execution():
    print("Processing definitions")
    if not os.path.isfile(EXECUTION):
        return

    with open(EXECUTION, "r") as exe_fh:
        for line in exe_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*)', line)
            if m:
                src_file = m.group(1)
                func = m.group(2)
                def_line = m.group(3)
                func_type = m.group(4)

                if func in KM["functions"] and src_file in KM["functions"][func]:
                    k_error("Function is defined more than once: '{}' '{}'".format(func, src_file))
                    continue

                KM["functions"][func][src_file]["type"] = func_type
                KM["functions"][func][src_file]["defined on line"] = def_line


def process_exported():
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


def process_define():
    if not os.path.isfile(DEFINE):
        return
    print("Processing macro functions")

    with open(DEFINE, "r") as def_fh:
        for line in def_fh:
            m = re.match(r'(\S*) (\S*) (\S*)', line)
            if m:
                src_file = m.group(1)
                macro = m.group(2)
                line = m.group(3)

                KM["macros"][macro][src_file] = line


def process_decl():
    print("Processing declarations")
    if not os.path.isfile(DECL):
        return

    with open(DECL, "r") as decl_fh:
        for line in decl_fh:
            m = re.match(r'(\S*) (\S*) (\S*)', line)
            if m:
                decl_file = m.group(1)
                decl_name = m.group(2)
                def_line = m.group(3)

                if decl_name not in KM["functions"]:
                    continue

                for src_file in KM["functions"][decl_name]:
                    if src_file == decl_file:
                        KM["functions"][decl_name][src_file]["declared in"][decl_file] = def_line
                    elif list(set(KM["source files"][src_file]["compiled to"]) &
                              set(KM["source files"][decl_file]["compiled to"])):
                        KM["functions"][decl_name][src_file]["declared in"][decl_file] = def_line
                    elif src_file == "unknown":
                        KM["functions"][decl_name]["unknown"]["declared in"][decl_file] = def_line


def process_init():
    if not os.path.isfile(INIT):
        return
    print("Processing init functions")

    with open(INIT, "r") as init_fh:
        for line in init_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                file = m.group(1)
                func = m.group(2)

                KM["functions"][func][file]["init"] = True


def process_exit():
    if not os.path.isfile(EXIT):
        return
    print("Processing exit functions")

    with open(EXIT, "r") as exit_fh:
        for line in exit_fh:
            m = re.match(r'(\S*) (\S*)', line)
            if m:
                file = m.group(1)
                func = m.group(2)

                KM["functions"][func][file]["exit"] = True


def process_call():
    if not os.path.isfile(CALL):
        return
    print("Processing calls")

    with open(CALL, "r") as call_fh:
        for line in call_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*) (\S*)', line)
            if m:
                context_file = m.group(1)
                context_func = m.group(2)
                func = m.group(3)
                call_line = m.group(4)
                call_type = m.group(5)

                match_call_and_def(context_file, context_func, func, call_line, call_type)


def match_call_and_def(context_file, context_func, func, call_line, call_type):
    # __builtin and __compiletime functions are not included in KM
    if re.match(r'(__builtin)|(__compiletime)', func):
        return
    if re.match(r'__bad', func) and func not in KM["functions"]:
        return

    if func not in KM["functions"]:
        KM["functions"][func]["unknown"]["defined on line"] = "unknown"
        KM["functions"][func]["unknown"]["type"] = call_type
        KM["functions"][func]["unknown"]["called in"][context_func][context_file][call_line] = 0

        k_error("Without definition: {}".format(func))
        return

    # For each function call there can be many definitions with the same name, defined in different files.
    # possible_files is a list of them.
    possible_files = []
    for possible_file in KM["functions"][func]:
        if possible_file == "unknown":
            continue
        elif (KM["functions"][func][possible_file]["type"] == call_type or
              KM["functions"][func][possible_file]["type"] == "exported"):
            possible_files.append(possible_file)

    # If there is no possible definitions:
    if len(possible_files) == 0:
        KM["functions"][func]["unknown"]["defined on line"] = "unknown"
        KM["functions"][func]["unknown"]["type"] = call_type
        KM["functions"][func]["unknown"]["called in"][context_func][context_file][call_line] = 0

        # It will be a kartographer's fault until it supports aliases
        if not re.match(r'__mem', func):
            k_error("No possible definitions: {}".format(func))
    else:
        # Assign priority number for each possible definition. Examples:
        # 5 means that definition is located in the same file as the call
        # 4 - in the same translation unit
        # 3 - in the object file that is linked with the object file that contains the call
        # 2 reserved for exported functions (Linux kernel only)
        # 1 - TODO: investigate this case
        # 0 - definition is not found
        matched_files = [None] * 6
        for x in range(0, len(matched_files)):
            matched_files[x] = []

        for possible_file in possible_files:
            if possible_file == context_file:
                matched_files[5].append(possible_file)
            elif (list(set(KM["source files"][possible_file]["compiled to"]) &
                       set(KM["source files"][context_file]["compiled to"]))):
                matched_files[4].append(possible_file)
            elif (call_type == "global" and
                  ("used in" in KM["source files"][possible_file] and
                   "used in" in KM["source files"][context_file] and
                   list(set(KM["source files"][possible_file]["used in"]) &
                        set(KM["source files"][context_file]["used in"])))):
                matched_files[3].append(possible_file)
            elif (call_type == "global" and KM["functions"][func][possible_file]["type"] == "exported"):
                matched_files[2].append(possible_file)
            elif call_type == "global":
                for decl_file in KM["functions"][func][possible_file]["declared in"]:
                    if list(set(KM["source files"][decl_file]["compiled to"]) &
                            set(KM["source files"][context_file]["compiled to"])):
                        matched_files[1].append(possible_file)

        matched_files[0].append("unknown")

        for x in range(len(matched_files) - 1, -1, -1):
            if matched_files[x] != []:
                if len(matched_files[x]) > 1:
                    k_error("Multiple matches: {} {}".format(func, context_func))
                for possible_file in matched_files[x]:
                    KM["functions"][func][possible_file]["called in"][context_func][context_file][call_line] = x

                    if possible_file == "unknown":
                        KM["functions"][func][possible_file]["defined on line"] = "unknown"
                        KM["functions"][func][possible_file]["type"] = call_type

                        k_error("Can't match definition: {} {}".format(func, context_file))
                break


def process_callp():
    if not os.path.isfile(CALLP):
        return

    with open(CALLP, "r") as callp_fh:
        for line in callp_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*)', line)
            if m:
                context_file = m.group(1)
                context_func = m.group(2)
                func_ptr = m.group(3)
                call_line = m.group(4)

                KM["functions"][context_func][context_file]["calls by pointer"][func_ptr][call_line] = 1


def process_init_global():
    if not os.path.isfile(INIT_GLOBAL):
        return

    variables = nested_dict()

    with open(INIT_GLOBAL, "r") as init_fh:
        for line in init_fh:
            m = re.match(r'^(\S+) (\w+)\|\|(.*)', line)
            if m:
                file = m.group(1)
                var_name = m.group(2)
                rest = m.group(3)

                rest = re.sub(r'& ', '', rest)
                var_values_and_types = rest.split('||')

                for value_and_type in var_values_and_types:
                    m = re.match(r'(.*):(\d)', value_and_type)
                    if m:
                        value = m.group(1)
                        valueType = m.group(2)
                        variables[var_name][file]["values"][value] = valueType

    for var_name in variables:
        for file in variables[var_name]:
            viewed = nested_dict()
            match_var_and_value(variables, viewed, var_name, file, var_name, file)


def match_var_and_value(variables, viewed, var_name, file, origvar_name, original_file):
    if var_name in viewed and file in viewed[var_name]:
        return

    viewed[var_name][file] = 1

    for value in variables[var_name][file]["values"]:
        if variables[var_name][file]["values"][value] == "1":
            KM["variables"][origvar_name][original_file]["values"][value] = 1
        elif value in variables:
            for possible_file in variables[value]:
                if possible_file == file:
                    match_var_and_value(variables, viewed, value, possible_file, origvar_name, original_file)
                elif (list(set(KM["source files"][possible_file]["compiled to"]) &
                           set(KM["source files"][file]["compiled to"]))):
                    match_var_and_value(variables, viewed, value, possible_file, origvar_name, original_file)


def process_use_var():
    if not os.path.isfile(USE_VAR):
        return

    with open(USE_VAR, "r") as use_var_fh:
        for file_line in use_var_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*)', file_line)
            if m:
                context_file = m.group(1)
                context_func = m.group(2)
                var_name = m.group(3)
                line = m.group(4)

                if var_name in KM["variables"]:
                    for possible_file in KM["variables"][var_name]:
                        if possible_file == context_file:
                            for func in KM["variables"][var_name][possible_file]["values"]:
                                match_use_and_def(context_file, context_func, func, line)
                        elif (list(set(KM["source files"][possible_file]["compiled to"]) &
                                   set(KM["source files"][context_file]["compiled to"]))):
                            for func in KM["variables"][var_name][possible_file]["values"]:
                                match_use_and_def(context_file, context_func, func, line)
                        elif ("used in" in KM["source files"][possible_file] and
                                "used in" in KM["source files"][context_file] and
                                list(set(KM["source files"][possible_file]["used in"]) &
                                     set(KM["source files"][context_file]["used in"]))):
                            for func in KM["variables"][var_name][possible_file]["values"]:
                                match_use_and_def(context_file, context_func, func, line)


def process_use_func():
    if not os.path.isfile(USE_FUNC):
        return

    with open(USE_FUNC, "r") as use_func_fh:
        for file_line in use_func_fh:
            m = re.match(r'(\S*) (\S*) (\S*) (\S*)', file_line)
            if m:
                context_file = m.group(1)
                context_func = m.group(2)
                func = m.group(3)
                line = m.group(4)

                match_use_and_def(context_file, context_func, func, line)


def match_use_and_def(context_file, context_func, func, line):
    if re.match(r'(__builtin)|(__compiletime)', func):
        return
    if func not in KM["functions"]:
        k_error("Use of function without definition: {}".format(func))
        return

    possible_files = []
    for possible_file in KM["functions"][func]:
        if possible_file == "unknown":
            continue
        possible_files.append(possible_file)

    if len(possible_files) == 0:
        k_error("No possible definitions for use: {}".format(func))
    else:
        matched_files = [None] * 4
        for x in range(0, len(matched_files)):
            matched_files[x] = []

        for possible_file in possible_files:
            if possible_file == context_file:
                matched_files[3].append(possible_file)
            elif (list(set(KM["source files"][possible_file]["compiled to"]) &
                       set(KM["source files"][context_file]["compiled to"]))):
                matched_files[2].append(possible_file)
            elif ("used in" in KM["source files"][possible_file] and
                    "used in" in KM["source files"][context_file] and
                    list(set(KM["source files"][possible_file]["used in"]) &
                         set(KM["source files"][context_file]["used in"]))):
                matched_files[1].append(possible_file)

        matched_files[0].append("unknown")

        for x in range(len(matched_files) - 1, -1, -1):
            if matched_files[x] != []:
                if len(matched_files[x]) > 1:
                    k_error("Multiple matches for use: {} call in {}".format(func, context_func))
                for possible_file in matched_files[x]:
                    if context_func == "NULL":
                        KM["functions"][func][possible_file]["used in file"][context_file][line] = x
                    else:
                        KM["functions"][func][possible_file]["used in func"][context_func][context_file][line] = x

                    if possible_file == "unknown":
                        k_error("Can't match definition for use: {} {}".format(func, context_file))
                break


def reverse_km():
    for func in KM["functions"]:
        for file in KM["functions"][func]:
            def_line = KM["functions"][func][file]["defined on line"]
            KM["source files"][file]["defines"][func] = def_line

            if "called in" in KM["functions"][func][file]:
                for context_func in KM["functions"][func][file]["called in"]:
                    for context_file in KM["functions"][func][file]["called in"][context_func]:
                        KM["functions"][context_func][context_file]["calls"][func][file] = KM["functions"][func][file]["called in"][context_func][context_file]
            if "used in func" in KM["functions"][func][file]:
                for context_func in KM["functions"][func][file]["used in func"]:
                    for context_file in KM["functions"][func][file]["used in func"][context_func]:
                        KM["functions"][context_func][context_file]["uses"][func][file] = KM["functions"][func][file]["used in func"][context_func][context_file]
    for macro in KM["macros"]:
        for file in KM["macros"][macro]:
            KM["source files"][file]["defines"][macro] = 1


def clean_error_log():
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


def store_km(km_file):
    """
    Serializes generated model in a form of JSON.
    """

    print("Serializing generated model")
    with open(km_file, "w") as km_fh:
        json.dump(KM, km_fh, sort_keys=True, indent=4)


def k_error(str):
    """
    Prints to ERR_LOG file an error message related to work of the generator itself.
    """

    with open(ERR_LOG, "a") as err_fh:
        err_fh.write("{}\n".format(str))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--bc', metavar='PATH', help='set PATH to json with build commands', required=True)
    parser.add_argument('--cif', metavar='PATH', help='set PATH to CIF executable', default="cif")
    parser.add_argument('--km', metavar='FILE', help='store generated KM in FILE', default=WD + "/km.json")
    options = parser.parse_args()

    # Only --bc option is required - it specifies path to json file that contains linking and compilation commands (build commands) of analysed project.
    if not os.path.isfile(options.bc):
        sys.exit("{} is not a file".format(options.bc))

    # --cif option is not required, but in this case it will be searched in $PATH

    if os.path.isdir(WD):
        sys.exit("Working directory {} already exists. Please delete or backup it and relunch the script".format(WD))
    else:
        os.mkdir(WD)

    aspect = gen_info_requests()
    src = process_build_commands(options.bc, options.cif, aspect)

    normalize_cif_output(src)

    # Process files generated by CIF
    process_of()
    process_execution()
    process_exported()
    process_define()
    process_init()
    process_exit()
    process_decl()

    process_call()
    process_callp()
    process_init_global()
    process_use_var()
    process_use_func()
    reverse_km()
    clean_error_log()

    store_km(options.km)
    print("Complete")
