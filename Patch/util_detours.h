// util_detours.h
#pragma once

#include <detours.h>

struct _DETOUR_ALIGN
{
    BYTE    obTarget : 3;
    BYTE    obTrampoline : 5;
};

C_ASSERT(sizeof(_DETOUR_ALIGN) == 1);

#ifdef DETOURS_X86

struct _DETOUR_TRAMPOLINE
{
    BYTE            rbCode[30];     // target code + jmp to pbRemain
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[22];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

#endif
