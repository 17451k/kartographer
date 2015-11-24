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

import collections
import json
import os
import re
import sys
from termcolor import colored

type_color = 'yellow'
func_color = 'green'
file_color = 'red'
line_color = 'yellow'
object_color = 'green'

USAGE = """
     Usage:

        This script reads commands from STDIN after launch, in an infinite loop.
        Commands: -f  <funciton name> (e.g. fls64)
                  -m  <macro name>    (e.g. mutex_lock)
                  -s  <source file>   (e.g. sound/sound_core.c)
                  -o  <object file>   (e.g. sound/sound_core.o)

"""


def nested_dict():
    return collections.defaultdict(nested_dict)

KM = nested_dict()


def KM_dump(mode, name):
    if re.search(r'-f', mode):
        if name not in KM["functions"]:
            print("Function {} is not found in KM".format(colored(name, func_color)))
        else:
            for src_file in KM["functions"][name]:
                func_type = KM["functions"][name][src_file]["type"]
                decl_line = KM["functions"][name][src_file]["decl line"]
                if "signature" in KM["functions"][name][src_file]:
                    signature = KM["functions"][name][src_file]["signature"]
                else:
                    signature = name

                print("{} function {} is defined in {} in line {} and:".format(
                      colored(func_type, type_color),
                      colored(signature, func_color),
                      colored(src_file, file_color),
                      colored(decl_line, line_color)))

                if "declared in" not in KM["functions"][name][src_file]:
                    print("  is not declared anywhere")
                else:
                    print("  is declared in:")

                    for declared in KM["functions"][name][src_file]["declared in"]:
                        print("    {}".format(colored(declared, file_color)))

                if "called in" not in KM["functions"][name][src_file]:
                    print("  is not called anywhere")
                else:
                    print("  is called in:")

                    for context_func in KM["functions"][name][src_file]["called in"]:
                        for context_file in KM["functions"][name][src_file]["called in"][context_func]:
                            for call_line in KM["functions"][name][src_file]["called in"][context_func][context_file]:
                                level = KM["functions"][name][src_file]["called in"][context_func][context_file][call_line]
                            lines = ' '.join(list(KM["functions"][name][src_file]["called in"][context_func][context_file]))
                            print("    {}: {:<55} in   {:<55} in lines {}".format(
                                  level,
                                  colored(context_func, func_color),
                                  colored(context_file, file_color),
                                  colored(lines, line_color)))

                if "calls" not in KM["functions"][name][src_file]:
                    print("  doesn't call anything")
                else:
                    print("  calls:")

                    for called_func in KM["functions"][name][src_file]["calls"]:
                        for called_file in KM["functions"][name][src_file]["calls"][called_func]:
                            for call_line in KM["functions"][name][src_file]["calls"][called_func][called_file]:
                                level = KM["functions"][name][src_file]["calls"][called_func][called_file][call_line]
                            lines = ' '.join(list(KM["functions"][name][src_file]["calls"][called_func][called_file]))
                            print("    {}: {:<55} from {:<55} in lines {}".format(
                                  level,
                                  colored(called_func, func_color),
                                  colored(called_file, file_color),
                                  colored(lines, line_color)))

                if "calls by pointer" not in KM["functions"][name][src_file]:
                    print("  doesn't call anything by pointer")
                else:
                    print("  calls by pointer:")

                    for pointer in KM["functions"][name][src_file]["calls by pointer"]:
                        lines = ' '.join(list(KM["functions"][name][src_file]["calls by pointer"][pointer]))
                        print("    {:<58} in lines {}".format(
                              colored(pointer, func_color),
                              colored(lines, line_color)))
    elif re.search(r'-m', mode):
        if name not in KM["macros"]:
            print("Macro {} is not found in KM".format(colored(name, func_color)))
        else:
            for src_file in KM["macros"][name]:
                print("Macro function {} is defined in {}".format(
                      colored(name, func_color),
                      colored(src_file, file_color)))
    elif re.search(r'-s', mode):
        if name not in KM["source files"]:
            print("Source file {} is not found in KM".format(colored(name, file_color)))
        else:
            print("Source file {}:".format(colored(name, file_color)))

            if "defines" not in KM["source files"][name]:
                print("  doesn't define anything")
            else:
                print("  defines:")
                for func_or_macro in KM["source files"][name]["defines"]:
                    print("    {}".format(colored(func_or_macro, func_color)))

            if "compiled to" not in KM["source files"][name]:
                print("  is not compiled to an object file")
            else:
                print("  is compiled to:")
                for object_file in KM["source files"][name]["compiled to"]:
                    print("    {}".format(colored(object_file, object_color)))

            if "used in" not in KM["source files"][name]:
                print("  is not used in object files")
            else:
                print("  is used in next object files:")
                for obj in KM["source files"][name]["used in"]:
                    print("    {}".format(colored(obj, object_color)))
    elif re.search(r'-o', mode):
        if name not in KM["object files"]:
            print("Object file {} is not found in KM".format(colored(name, object_color)))
        else:
            print("Object file {}:".format(colored(name, object_color)))

            if "compiled from" not in KM["object files"][name]:
                print("  is not compiled from a source file")
            else:
                print("  is compiled from:")
                for source_file in KM["object files"][name]["compiled from"]:
                    print("    {}".format(colored(source_file, file_color)))

            if "linked from" not in KM["object files"][name]:
                print("  is not linked from an object file")
            else:
                print("  is linked from:")
                for source_file in KM["object files"][name]["linked from"]:
                    print("    {}".format(colored(source_file, file_color)))

            if "linked to" not in KM["object files"][name]:
                print("  is not linked to an object file")
            else:
                print("  is linked to:")
                for obj in KM["object files"][name]["linked to"]:
                    print("    {}".format(colored(obj, object_color)))


if __name__ == "__main__":
    if len(sys.argv) == 1 or not os.path.isfile(sys.argv[1]):
        sys.exit("Can not find Kernel Model. Please run this script with <path to kernel model> as option.")

    print(USAGE)

    km_status = "not loaded"

    while 1:
        command = input("KM: ").split(" ")

        if len(command) < 2 or not re.search(r'-f|-m|-s|-o', command[0]):
            print("Wrong arguments")
            continue
        elif km_status == "not loaded":
            with open(sys.argv[1], "r") as km_fh:
                try:
                    KM = json.load(km_fh)
                    km_status = "loaded"
                except json.decoder.JSONDecodeError as e:
                    sys.exit("Specified file is not a valid JSON")

        KM_dump(command[0], command[1])
        print()
