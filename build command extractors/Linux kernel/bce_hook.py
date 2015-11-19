#! /usr/bin/python3

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

import fcntl
import os
import re
import sys

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        sys.exit("Something went wrong")

    cmd_type = ""
    xml_dict = dict()
    curr_opt = ""
    bce_xml = os.environ['BC_XML']

    for opt in sys.argv:
        if opt in ["CC", "LD", "LDM", "OPTS", "OUT"]:
            curr_opt = opt
            continue

        if curr_opt == "CC" or curr_opt == "LD" or curr_opt == "LDM":
            if "in" in xml_dict:
                xml_dict["in"].append(opt)
            else:
                xml_dict["in"] = [opt]

            cmd_type = curr_opt.lower()
        elif curr_opt == "OPTS":
            if "opts" in xml_dict:
                xml_dict["opts"].append(opt)
            else:
                xml_dict["opts"] = [opt]
        elif curr_opt == "OUT":
            if "out" in xml_dict:
                xml_dict["out"].append(opt)
            else:
                xml_dict["out"] = [opt]

    with open(bce_xml, "a") as xml_fh:
        fcntl.lockf(xml_fh, fcntl.LOCK_EX)

        xml_fh.write("  <{}>\n".format(cmd_type))

        for element in xml_dict["in"]:
            if not re.search(r'\.mod\.o', element):
                xml_fh.write("    <in>{}</in>\n".format(element))
        for element in xml_dict["out"]:
            xml_fh.write("    <out>{}</out>\n".format(element))
        if "opts" in xml_dict:
            for element in xml_dict["opts"]:
                xml_fh.write("    <opt>{}</opt>\n".format(element))

        xml_fh.write("  </{}>\n".format(cmd_type))
