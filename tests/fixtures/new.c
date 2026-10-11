/* Same exported function with an explicit invalid-index guard. */
__declspec(dllexport) int read_item(const int *items, int length, int index) {
    if (items == 0 || index < 0 || index >= length) return -1;
    return items[index];
}
