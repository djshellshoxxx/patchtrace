// Authored ABI probe. It reads no package and only prints SDK layout facts.
#include <windows.h>
#include <fdi.h>
#include <cstddef>
#include <cstdio>
#include <type_traits>

static_assert(sizeof(void*) == 8, "Windows AMD64 required");
static_assert(sizeof(long) == 4 && sizeof(int) == 4 && sizeof(BOOL) == 4, "Win32 integer ABI");
static_assert(sizeof(ULONG) == 4 && sizeof(UINT) == 4 && sizeof(USHORT) == 2, "Win32 unsigned ABI");
static_assert(std::is_same<PFNALLOC, void* (__cdecl*)(ULONG)>::value, "PFNALLOC");
static_assert(std::is_same<PFNFREE, void (__cdecl*)(void*)>::value, "PFNFREE");
static_assert(std::is_same<PFNOPEN, INT_PTR (__cdecl*)(LPSTR, int, int)>::value, "PFNOPEN");
static_assert(std::is_same<PFNREAD, UINT (__cdecl*)(INT_PTR, void*, UINT)>::value, "PFNREAD");
static_assert(std::is_same<PFNWRITE, UINT (__cdecl*)(INT_PTR, void*, UINT)>::value, "PFNWRITE");
static_assert(std::is_same<PFNCLOSE, int (__cdecl*)(INT_PTR)>::value, "PFNCLOSE");
static_assert(std::is_same<PFNSEEK, long (__cdecl*)(INT_PTR, long, int)>::value, "PFNSEEK");
static_assert(std::is_same<PFNFDINOTIFY,
              INT_PTR (__cdecl*)(FDINOTIFICATIONTYPE, PFDINOTIFICATION)>::value, "PFNFDINOTIFY");
static_assert(std::is_same<decltype(&FDICreate), HFDI (__cdecl*)(PFNALLOC, PFNFREE, PFNOPEN,
              PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK, int, PERF)>::value, "FDICreate");
static_assert(std::is_same<decltype(&FDIIsCabinet), BOOL (__cdecl*)(HFDI, INT_PTR, PFDICABINETINFO)>::value,
              "FDIIsCabinet");
static_assert(std::is_same<decltype(&FDICopy), BOOL (__cdecl*)(HFDI, LPSTR, LPSTR, int,
              PFNFDINOTIFY, PFNFDIDECRYPT, void*)>::value, "FDICopy");
static_assert(std::is_same<decltype(&FDIDestroy), BOOL (__cdecl*)(HFDI)>::value, "FDIDestroy");

#define SIZE_OF(type) std::printf(",\"" #type ".size\":%zu", sizeof(type))
#define OFFSET_OF(type, field) std::printf(",\"" #type "." #field "\":%zu", offsetof(type, field))

int main() {
    std::printf("{\"pointer_bits\":%zu", sizeof(void*) * 8);
    SIZE_OF(ERF);
    OFFSET_OF(ERF, erfOper); OFFSET_OF(ERF, erfType); OFFSET_OF(ERF, fError);
    SIZE_OF(FDICABINETINFO);
    OFFSET_OF(FDICABINETINFO, cbCabinet); OFFSET_OF(FDICABINETINFO, cFolders);
    OFFSET_OF(FDICABINETINFO, cFiles); OFFSET_OF(FDICABINETINFO, setID);
    OFFSET_OF(FDICABINETINFO, iCabinet); OFFSET_OF(FDICABINETINFO, fReserve);
    OFFSET_OF(FDICABINETINFO, hasprev); OFFSET_OF(FDICABINETINFO, hasnext);
    SIZE_OF(FDINOTIFICATION);
    OFFSET_OF(FDINOTIFICATION, cb); OFFSET_OF(FDINOTIFICATION, psz1);
    OFFSET_OF(FDINOTIFICATION, psz2); OFFSET_OF(FDINOTIFICATION, psz3);
    OFFSET_OF(FDINOTIFICATION, pv); OFFSET_OF(FDINOTIFICATION, hf);
    OFFSET_OF(FDINOTIFICATION, date); OFFSET_OF(FDINOTIFICATION, time);
    OFFSET_OF(FDINOTIFICATION, attribs); OFFSET_OF(FDINOTIFICATION, setID);
    OFFSET_OF(FDINOTIFICATION, iCabinet); OFFSET_OF(FDINOTIFICATION, iFolder);
    OFFSET_OF(FDINOTIFICATION, fdie);
    SIZE_OF(FDISPILLFILE);
    OFFSET_OF(FDISPILLFILE, ach); OFFSET_OF(FDISPILLFILE, cbFile);
    std::printf("}\n");
    return 0;
}
