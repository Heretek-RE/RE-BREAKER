"""Drop-in DLL backends — 8 layers (Steam CEG + EOS, IOI, SEGA, Atlus, Sunblink, PA, Origin).

v0.2.0 ships the steam_ceg_dll backend (wraps the existing gbe_fork
`deploy-gbe-fork.sh` via subprocess). The 7 non-Steam backends are SCAFFOLD
for Phase 2 (the C/C++ stub DLLs are out of scope for v0.2.0).
"""
