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
import collections
import os
import json
import re
import sys


def nested_dict():
    return collections.defaultdict(nested_dict)

KM = nested_dict()


def load_km(km_file):
    global KM

    print("Loading KM")
    with open(km_file, "r") as km_fh:
        try:
            KM = json.load(km_fh)
        except json.decoder.JSONDecodeError as e:
            sys.exit("Specified file is not a valid JSON")


def do_mapping(map_file):
    print("Processing of mapping file")

    mapping = nested_dict()

    with open(map_file, "r") as map_fh:
        for file_line in map_fh:
            m = re.match(r'(\S*) (\S*)', file_line)
            if m:
                mapping[m.group(1)][m.group(2)] = 1

    for func in KM["functions"]:
        for file in KM["functions"][func]:
            if "calls by pointer" in KM["functions"][func][file]:
                for ptr in KM["functions"][func][file]["calls by pointer"]:
                    for call_line in KM["functions"][func][file]["calls by pointer"][ptr]:
                        if ptr in mapping:
                            for func_ptr in mapping[ptr]:
                                if func_ptr in KM["functions"]:
                                    for file_ptr in KM["functions"][func_ptr]:
                                        if "called in" not in KM["functions"][func_ptr][file_ptr]:
                                            KM["functions"][func_ptr][file_ptr]["called in"] = nested_dict()
                                        if func not in KM["functions"][func_ptr][file_ptr]["called in"]:
                                            KM["functions"][func_ptr][file_ptr]["called in"][func] = nested_dict()
                                        if file not in KM["functions"][func_ptr][file_ptr]["called in"][func]:
                                            KM["functions"][func_ptr][file_ptr]["called in"][func][file] = nested_dict()

                                        if "calls" not in KM["functions"][func][file]:
                                            KM["functions"][func][file]["calls"] = nested_dict()
                                        if func_ptr not in KM["functions"][func_ptr][file_ptr]["called in"]:
                                            KM["functions"][func][file]["calls"][func_ptr] = nested_dict()
                                        if file_ptr not in KM["functions"][func][file]["calls"][func_ptr]:
                                            KM["functions"][func][file]["calls"][func_ptr][file_ptr] = nested_dict()

                                        KM["functions"][func_ptr][file_ptr]["called in"][func][file][call_line] = 9
                                        KM["functions"][func][file]["calls"][func_ptr][file_ptr][call_line] = 9
                                else:
                                    print("WARNING: функция '{}' не найдена".format(func_ptr))


def store_km(km_file):
    """
    Serializes generated model in a form of JSON.
    """

    print("Serializing patched KM to {} file".format(km_file))
    with open(km_file, "w") as km_fh:
        json.dump(KM, km_fh, sort_keys=True, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--map', metavar='PATH', help='set PATH to file with mapping', required=True)
    parser.add_argument('--km', metavar='PATH', help='PATH to KM that need to be patched', required=True)
    options = parser.parse_args()

    if not os.path.isfile(options.map):
        sys.exit("{} is not a file".format(options.map))

    if not os.path.isfile(options.km):
        sys.exit("{} is not a file".format(options.km))

    load_km(options.km)
    do_mapping(options.map)
    store_km(options.km)
