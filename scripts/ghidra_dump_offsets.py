####################################################################################################
# This script will dump the offsets and class instances of FB Settings classes (eg. ClientSettings)
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
import json

from ghidra.app.util import XReferenceUtil
from ghidra.program.model.scalar import Scalar
from ghidra.program.util import DefinedDataIterator

# Type hinting only
if __name__ != "__main__":
    from ghidra.ghidra_builtins import currentProgram, getInstructionAt, getDataAt, findBytes


def get_string_pointers():
    strings = DefinedDataIterator.definedStrings(currentProgram)

    # Get the names for now. Each class will have an -Array one too, so we can filter for those
    class_names = []
    for string in strings:
        string = string.getValue().encode("utf-8").decode("utf-8")
        if string.endswith("-Array"):
            class_names.append(string.replace("-Array", ""))

    # Now get the xrefs
    strings = DefinedDataIterator.definedStrings(currentProgram)  # Dunno why this needs to be called again

    all_refs = {}
    for string in strings:
        string_val = string.getValue().encode("utf-8").decode("utf-8")
        if string_val not in class_names:
            continue

        refs = XReferenceUtil.getXRefList(string)
        for ref in refs:
            ref_addr = currentProgram.getAddressFactory().getAddress(str(ref))
            ref_data = getDataAt(ref_addr)

            # Found the actual pointer, not some direct reference
            if ref_data and ref_data.isPointer():
                all_refs[string_val] = ref_addr
                break

    return all_refs


def search_memory(string):
    print("Searching memory for", string)

    addr = currentProgram.getMinAddress()
    while True:
        addr = findBytes(addr, string)
        if not addr:
            return
        yield addr
        addr = addr.add(20)  # At the very least from the pattern, may overlap a bit


def get_strings():
    for instr in currentProgram.getListing().getInstructions(True):
        op2 = instr.getOperandReferences(1)
        if not op2:
            continue

        to = op2[0].getToAddress()
        fro = op2[0].getFromAddress()

        # See if to is a double pointer to a string
        ptr1 = getDataAt(to)
        if not ptr1 or not ptr1.isPointer():
            continue

        ptr2 = getDataAt(ptr1.getValue())
        if not ptr2 or not ptr2.isPointer():
            continue

        text = getDataAt(ptr2.getValue())
        if not text:
            continue

        text = str(text)
        if not text.startswith("ds"):
            continue

        text = text.split("\"")[1]

        yield fro, text

def get_pointer_uses():
    used = {}
    ban = []
    for fro, text in get_strings():
        fro = fro.toString()
        if text in used:
            ban.append(fro)

        used[text] = fro

    keep = {k: v for k, v in used.items() if k not in ban}

    print(json.dumps(keep, indent=2))
    print(ban)

def dump():

    print("Finding classes")
    pointer_uses = get_pointer_uses()
    print("Found", sum([len(v) for k, v in pointer_uses.items()]), "classes")

    print("Finding strings...")
    string_pointers = get_string_pointers()
    print("Found", len(string_pointers), "Strings")

    for class_name, class_offset in pointer_uses.items():
        try:
            class_def = string_pointers[class_name]
            print(class_name, class_offset, class_def)
        except KeyError:
            print("Skipped " + class_name)


if __name__ == "__main__":
    get_pointer_uses()
