/* Benign static bounds-check regression fixture; never executed by PatchTrace. */
__declspec(dllexport) int read_item(const int *items, int length, int index) {
    return items[index];
}
