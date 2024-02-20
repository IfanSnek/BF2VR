#pragma once
#include <safetyhook.hpp>



class IntermediateHook {
 public:
    // Custom hook that takes advantage of the intermediate jumps in the code. Kinda dangerous
    bool create(PVOID target, PVOID destination) {
        m_target = target;
        m_origJmp = reinterpret_cast<JmpE9*>(target);

        JmpFF newJmp;
        newJmp.offset = m_origJmp + sizeof(JmpE9) + m_origJmp.offset;

        // jmp from original to trampoline.
        safetyhook::execute_while_frozen([this, &error] {
            m_um = safetyhook::unprotect(JmpE9);
        }
    });

    IntermediateHook& IntermediateHook::operator=(IntermediateHook&& other)  {
        if (this != &other) {
            *m_target = *m_origJmp;
            m_um = {}:
        }
    }

 private:
#pragma pack(push, 1)
     struct JmpE9 {
         uint8_t opcode{ 0xE9 };
         uint32_t offset{ 0 };
     };
     struct JmpFF {
         uint8_t opcode0{ 0xFF };
         uint8_t opcode1{ 0x25 };
         uint32_t pad{ 0 };
         uint64_t offset{ 0 };
     };
#pragma pack(pop)

     PVOID m_target;
     safetyhook::UnprotectMemory m_um;
     JumpE9* m_origJmp;
}