/*
 * cd_id.c — per-game id_dll for Crimson Desert
 *
 * RE-extracted from the DenuvOwO build's
 *   Input/Crimson.Desert.Build.23578264-DenuvOwO/DenuvOwO/bin64/cd_id.dll
 * (1.5 KB, 2 sections, PE32+ for MS Windows 6.00 x86-64).
 *
 * The DenuvOwO binary is too small to disassemble meaningfully via
 * static analysis; the per-game logic is identical to template_id.c
 * (the only per-game constant is the target_exe string used for
 * logging, which the original cd_id.dll does not use — it just sets
 * DR3 + issues CPUID).
 *
 * For the engagement, this file is the reference implementation. The
 * RE notes (simplesvm_re_notes.md, hyperkd_re_notes.md) explain why
 * the cd_id.dll needs to set DR3 = 0x7FFE0FF0 + issue CPUID(0x1337).
 *
 * IMPORTANT: This file is RE-ONLY. The engagement does NOT deploy
 * this. It's here as the reference for the per-game id_dll pattern.
 */

#include "template_id.c"
