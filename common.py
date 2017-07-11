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

import os
import subprocess
import re


def process(argv):
    cmd = os.path.basename(argv[0])
    opts = argv[1:]

    with open(os.environ["RAW_CMDS"], "a") as cmd_fh:
        # Support for some cross-compilers
        if re.search(r'gcc$', cmd):
            cmd = "cc"
        elif re.search(r'ld$', cmd):
            cmd = "ld"
        elif re.search(r'ar$', cmd):
            cmd = "ar"
        elif re.search(r'objcopy$', cmd):
            cmd = "objcopy"
        cmd_fh.write('{}||{}\n'.format(os.getcwd(), "||".join([cmd] + opts)))

    # Restore original cmd
    cmd = os.path.basename(argv[0])

    # Eclude path where wrapper build command is located.
    os.environ["PATH"] = re.sub(r'^[^:]+:', '', os.environ["PATH"])

    # Execute original build command.
    try:
        return subprocess.check_call([cmd + ".bce"] + opts)
    except subprocess.CalledProcessError:
        return 1
    except OSError:  # executable not found
        return subprocess.call([cmd] + opts)
