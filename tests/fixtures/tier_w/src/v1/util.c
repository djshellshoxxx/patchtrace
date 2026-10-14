/* PatchTrace Tier-W self-made test fixture (MIT). A static `helper` that collides by name with util2.c. */
__attribute__((noinline)) static int helper(int x) { return (x ^ 0x5A) + (x >> 3); }

__declspec(dllexport) int util_mix(int x) { return helper(x) + 1; }
