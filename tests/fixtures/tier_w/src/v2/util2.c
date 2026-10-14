/* PatchTrace Tier-W self-made test fixture (MIT). The second static `helper` (name not unique). */
__attribute__((noinline)) static int helper(int x) { return x * 5 - (x << 2) + 9; }

__declspec(dllexport) int util2_mix(int x) { return helper(x) - 1; }
