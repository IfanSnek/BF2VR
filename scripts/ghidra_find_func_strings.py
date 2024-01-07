####################################################################################################
# This script will find all logged functions in a Frostbite game using Ghidra.
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

functionManager = currentProgram.getFunctionManager()

all_names = []
confirmed_loggers = []
for string in DefinedDataIterator.definedStrings(currentProgram):

    # Check if the string is a logged function (has a namespace) and is alphanumeric
    if string.getValue().find("::") != -1 and string.getValue().replace("::", "").isalnum():

        # Find the function/namespace name (usually before a space or end of string)
        func_new_name = string.getValue().split(" ")[0]

        # Iterate through all references to the string
        for ref in XReferenceUtil.getXRefList(string):

            # Get the address of the reference
            ref_addr = currentProgram.getAddressFactory().getAddress(str(ref))

            # Find the function that used the string. This will be the function we are trying to rename
            func = functionManager.getFunctionContaining(ref_addr)
            if func is None:
                continue

            func_orig_name = func.getName()

            # If the function has already been renamed, revert the name to the address. This means that there
            # are multiple references to strings in the same function, and the func_new_name is not
            # actually the name of the function.
            if func_orig_name in all_names:
                print("[Pass 1] Revoking name " + func_orig_name + " for " + func_new_name)
                func_orig_name = "FUN_" + str(func.getEntryPoint())

            # If the function name is not the same as the logged name, rename it
            if func_orig_name != func_new_name:
                print("[Pass 1] Renaming function at " + str(
                    func.getEntryPoint()) + " from " + func_orig_name + " to " + func_new_name)
                func.setName(func_new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                all_names.append(func_new_name)

            # Get nearest function call instruction after the usage of the string. This can
            # be done by slowly incrementing the address until we find a CALL instruction.
            counter = 0
            while not getInstructionAfter(ref_addr).getMnemonicString() == "CALL":
                ref_addr = ref_addr.add(1)

                # If we have gone too far, break
                counter += 1
                if counter > 30:
                    break
            # Go one more instruction to get the address of the CALL instruction
            instr = getInstructionAfter(ref_addr).getAddress()

            # Get the address of the function that was called. This sometimes fails, so we
            # need to catch the exception.
            try:
                logger_func = getInstructionAt(instr).getOpObjects(0)[0]
            except IndexError:
                continue

            # Ensure logger call is an address
            if not isinstance(logger_func, ghidra.program.model.address.Address):
                continue

            if getInstructionAt(logger_func) is None:
                continue

            # Frostbite is stupid and has a jmp to the final function call
            if getInstructionAt(logger_func).getMnemonicString() == "JMP":
                logger_func = getInstructionAt(logger_func).getOpObjects(0)[0]

            # Compile a list of all confirmed loggers
            if logger_func in confirmed_loggers:
                continue

            confirmed_loggers.append(logger_func)

    else:
        # Rename the function to the address if it has an invalid name. This cleans up
        # after previous runs of this script.
        func = functionManager.getFunctionContaining(string.getAddress())
        if func is None:
            continue
        func.setName("FUN_" + str(func.getEntryPoint()), ghidra.program.model.symbol.SourceType.USER_DEFINED)
        print("[Pass 1] Revoking name " + func.getName() + " for FUN_" + str(func.getEntryPoint()))

# Run another pass to rename any functions that were missed
all_names = []
for string in DefinedDataIterator.definedStrings(currentProgram):

    # Check if the string is alphanumeric, and is longer than 3 characters
    name = string.getValue().split(" ")[0]
    if not name.isalnum():
        continue
    if not len(name) > 3:
        continue

    # Iterate through all references to the string
    for ref in XReferenceUtil.getXRefList(string):

        # Get the address of the reference
        ref_addr = currentProgram.getAddressFactory().getAddress(str(ref))

        # Get nearest function call instruction after the usage of the string. This can
        # be done by slowly incrementing the address until we find a CALL instruction.
        counter = 0
        while not getInstructionAfter(ref_addr).getMnemonicString() == "CALL":
            ref_addr = ref_addr.add(1)

            # If we have gone too far, break
            counter += 1
            if counter > 30:
                break
        # Go one more instruction to get the address of the CALL instruction
        instr = getInstructionAfter(ref_addr).getAddress()

        # Get the address of the function that was called. This sometimes fails, so we
        # need to catch the exception.
        try:
            logger_func = getInstructionAt(instr).getOpObjects(0)[0]
        except IndexError:
            continue

        # Ensure logger call is an address
        if not isinstance(logger_func, ghidra.program.model.address.Address):
            continue

        # Ensure logger call is an address
        if getInstructionAt(logger_func) is None:
            continue

        # Frostbite is stupid and has a jmp to the final function call
        if getInstructionAt(logger_func).getMnemonicString() == "JMP":
            logger_func = getInstructionAt(logger_func).getOpObjects(0)[0]

        # Compile a list of all confirmed loggers
        if logger_func in confirmed_loggers:

            # Rename the function to the address
            func = functionManager.getFunctionContaining(ref_addr)
            if func is None:
                continue

            print("[Pass 2] Found missed logger at " + str(logger_func) + " for " + name)

            if func.getName() in all_names:
                # If the function has already been renamed, revert the name to the address
                name = "FUN_" + str(func.getEntryPoint())
                print("[Pass 2] Revoking name " + func.getName() + " for " + name)
            else:
                all_names.append(func.getName())

            if func.getName() != name:
                print("[Pass 2] Renaming function at " + str(
                    func.getEntryPoint()) + " from " + func.getName() + " to " + name)
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                all_names.append(name)
