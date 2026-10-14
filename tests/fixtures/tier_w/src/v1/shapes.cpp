// PatchTrace Tier-W self-made test fixture (MIT). C++ overloads and a member function: the PDB publics are
// mangled (unique per overload) while the demangled names collide.
__attribute__((noinline)) int scale(int v) { return v * 2 + 1; }
__attribute__((noinline)) long long scale(long long v) { return v * 3 - 1; }

struct Box {
    int w;
    int h;
    __attribute__((noinline)) int area() const;
};

int Box::area() const { return w * h; }

extern "C" __declspec(dllexport) int cpp_entry(int v) {
    Box b{v, v + 1};
    return scale(v) + static_cast<int>(scale(static_cast<long long>(v))) + b.area();
}
