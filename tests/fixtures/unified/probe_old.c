/* SPEC-31 S1 live/recorded fixture, OLD side. Hand-written for this repository (MIT); never executed. */
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);
__declspec(dllimport) int __stdcall MessageBoxA(void *h, const char *text, const char *caption, unsigned type);

int g_counter = 5;
static int g_table[4] = {11, 22, 33, 44};
const char *g_name = "hello probe string";
const char g_msg[] = "unique message for the probe";

__declspec(dllexport) int add_clamped(int a, int b) {
    int s = a + b;
    if (s > 1000) return 1000;
    if (s < -1000) return -1000;
    return s;
}

__declspec(dllexport) int dispatch(int op, int x) {
    switch (op) {
    case 0: return x + 1;
    case 1: return x * 3;
    case 2: return x - 7;
    case 3: return x ^ 0x55;
    case 4: return x << 2;
    case 5: return -x;
    case 6: return x + 100;
    default: return 0;
    }
}

__declspec(dllexport) int use_data(int i) {
    g_counter++;
    return g_table[i & 3] + g_counter;
}

__declspec(dllexport) int say(void) {
    return MessageBoxA(0, g_msg, "probe", 0x40);
}

__declspec(dllexport) unsigned long tick(void) {
    return GetTickCount() + (unsigned long)add_clamped(1, 2);
}

__declspec(dllexport) int loop_sum(const int *p, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < 0) continue;
        s += p[i];
    }
    return s;
}

__declspec(dllexport) int limit_check(int index, int length) {
    if (index < 0 || index >= length) return -1;
    return index * 4;
}
