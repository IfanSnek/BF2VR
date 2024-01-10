####################################################################################################
# This script will rename references to vtables to the name of the class that they are a part of.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU Lesser General Public License for more details.
#
####################################################################################################

from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
import os


def getVtablesFromClasses():
    lines = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "dump", "classes.h")).readlines()
    for i, line in enumerate(lines):
        if line.startswith("// Vtable : "):
            # First line is the vtable name
            vtable_addr = line.split("// Vtable : ")[1].strip()
            if vtable_addr == "0x000000000":
                continue
            # Third next line is the class name
            class_name = lines[i + 3].split("class ")[1].split(" ")[0].strip()
            yield vtable_addr, class_name


for vtable_addr, class_name in getVtablesFromClasses():
    # Get the vptr address
    vtable_addr = toAddr(int(vtable_addr, 16))
    # Get vptr at ADDR
    vptr = getDataAt(vtable_addr).getValue()
    # Get function at vptr
    func = getFunctionAt(vptr)
    if func is None:
        continue
    # Rename function to class name
    class_name = "vtable_" + class_name
    func.setName(class_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
    print("Renamed " + func.getName() + " to " + class_name)
