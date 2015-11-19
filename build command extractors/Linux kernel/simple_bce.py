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

import os
import os.path
import re
import multiprocessing

import subprocess
import sys
import tarfile
from optparse import OptionParser

PROCESSES = int(multiprocessing.cpu_count() / 2 + multiprocessing.cpu_count() % 2)
realpath = os.path.dirname(os.path.realpath(__file__))
cwd = os.getcwd()


def extract_kernel(kernel):
    if (tarfile.is_tarfile(kernel)):
        print("Extracting kernel")
        dirname = os.path.dirname(kernel)
        if dirname == "":
            dirname = "."
        folders_before_extractions = os.listdir(dirname)

        tar = tarfile.open(kernel)
        tar.extractall(path=dirname)
        tar.close()
        for folder in os.listdir(dirname):
            if (folder not in folders_before_extractions):
                return dirname + "/" + folder
        sys.exit("Can't find extracted kernel. Please use archive from www.kernel.org")
        # TODO: Improve kernel searching (Makefiles)
    else:
        sys.exit("'{}' is not a valid kernel archive. Please use one from kernel.org".format(kernel))


def patch_kernel(kernel):
    print("Patching makefiles")

    build_makefile = kernel + "/scripts/Makefile.build"
    modpost_makefile = kernel + "/scripts/Makefile.modpost"
    bce_hook = realpath + "/bce_hook.py"

    with open(build_makefile, "r") as build_fh:
        changes = 0
        build_string = build_fh.read()
        build_backup = build_string

        bce_regex = r'\t' + bce_hook + r' CC $< OPTS $(c_flags) -c OUT $(@D)/$(@F);\\\n\1'
        build_string = re.sub(r'(\t\$\(cmd_modversions\))', bce_regex, build_string)

        if build_string != build_backup:
            changes += 1
            build_backup = build_string

        bce_regex = r'\1' + bce_hook + r' LD $(link_multi_deps) OPTS $(ld_flags) -r OUT $@; '
        build_string = re.sub(r'(\ncmd_link_multi-y = )', bce_regex, build_string)

        if build_string != build_backup:
            changes += 1
        if changes != 2:
            sys.exit("Something went wrong. Can't modify makefile")

    with open(build_makefile, "w") as build_fh:
        build_fh.write(build_string)

    with open(modpost_makefile, "r") as modpost_fh:
        changes = 0
        modpost_string = modpost_fh.read()
        modpost_backup = modpost_string

        bce_regex = r'\1; ' + bce_hook + r' LDM $(filter-out FORCE,$^) OPTS OUT $@'
        modpost_string = re.sub(r'(-o \$@ \$\(filter-out FORCE,\$\^\))', bce_regex, modpost_string)

        if modpost_string != modpost_backup:
            changes += 1

        if changes != 1:
            sys.exit("Something went wrong. Can't modify makefile")

    with open(modpost_makefile, "w") as modpost_fh:
        modpost_fh.write(modpost_string)


def configure_kernel(kernel):
    print("Configuring kernel")

    proc = subprocess.Popen(["make", "-C", kernel, "allmodconfig"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if err:
        sys.exit("Something went wrong. Can't configure kernel")


def make_kernel(kernel):
    print("Making kernel")

    os.environ['BC_XML'] = cwd + "/bc.xml"
    with open(os.environ['BC_XML'], "w") as xml_fh:
        xml_fh.write("<root>\n")
        xml_fh.write("  <src>{}</src>\n".format(kernel))

    proc = subprocess.Popen(["make", "-C", kernel, "clean"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()
    if err:
        sys.exit("Something went wrong. Can't make clean kernel")

    proc = subprocess.Popen(["make", "-C", kernel, "-j" + str(PROCESSES)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = proc.communicate()

    with open(os.environ['BC_XML'], "a") as xml_fh:
        xml_fh.write("</root>\n")

    # if err:
        # sys.exit("Something went wrong. Can't make kernel")


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-k", "--kernel", dest="kernel", metavar="PATH",
                  help="set PATH to Linux kernel sources. It can be path to .tar.* archive")
    (options, args) = op.parse_args()

    kernel = options.kernel

    if kernel:
        if os.path.isfile(kernel):
            kernel = extract_kernel(kernel)

        if (not os.path.exists(kernel)):
            sys.exit("Linux kernel is not found")
    else:
        sys.exit("Linux kernel is not found. Please use -k parameter to specify path to the kernel")

    patch_kernel(kernel)
    configure_kernel(kernel)
    make_kernel(kernel)

    print("Complete")
