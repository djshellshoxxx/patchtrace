#@runtime Jython
# Ghidra script (SPEC-33 s5.2): exports `ghidra-symbols/1` for the current program. It must stay valid for Jython 2.7
# and CPython 3 (no f-strings, annotations, walrus or keyword-only arguments; a repository test enforces this).
# It reads only the stable Program API and never executes the analysed image.
# Usage (headless): -postScript ghidra_export_symbols.py <out.json>; PyGhidra driver: export(program, out_path).
import json

MAX_NAMES = 16


def _options(program):
    options = program.getOptions("Program Information")
    return {
        "loaded": bool(options.getBoolean("PDB Loaded", False)),
        "file": options.getString("PDB File", None),
        "guid": options.getString("PDB GUID", None),
        "age": options.getInt("PDB Age", -1),
    }


def _function(program, image_base, function):
    ranges = []
    for rng in function.getBody().getAddressRanges():
        ranges.append([int(rng.getMinAddress().getOffset() - image_base),
                       int(rng.getMaxAddress().getOffset() - image_base) + 1])
    ranges.sort()
    names = []
    for symbol in program.getSymbolTable().getSymbols(function.getEntryPoint()):
        source = symbol.getSource().toString()
        if source == "DEFAULT":
            continue
        names.append({"name": symbol.getName(), "source": source, "primary": bool(symbol.isPrimary())})
    return {"rva": int(function.getEntryPoint().getOffset() - image_base), "ranges": ranges,
            "thunk": bool(function.isThunk()), "names": sorted(names, key=lambda n: n["name"])[:MAX_NAMES]}


def export(program, out_path, limit=1000000):
    image_base = program.getImageBase().getOffset()
    functions, unnamed, truncated = [], 0, 0
    for function in program.getFunctionManager().getFunctions(True):
        if function.isExternal():
            continue
        item = _function(program, image_base, function)
        if not item["names"]:
            unnamed += 1
        elif len(functions) >= limit:
            truncated += 1
        else:
            functions.append(item)
    functions.sort(key=lambda f: f["rva"])
    pdb = _options(program)
    document = {
        "contract": "ghidra-symbols/1",
        "ghidra_version": "unknown",
        "python": "jython-or-cpython",
        "file_name": program.getName(),
        "image_base": int(image_base),
        "executable_sha256": program.getExecutableSHA256(),
        "pdb": {"loaded": pdb["loaded"], "file": pdb["file"], "guid": pdb["guid"],
                "age": pdb["age"] if pdb["age"] >= 0 else None},
        "functions": functions,
        "unnamed": unnamed,
        "truncated": truncated,
        "warnings": [],
    }
    handle = open(out_path, "w")
    try:
        handle.write(json.dumps(document, sort_keys=True))
    finally:
        handle.close()


try:
    _args = getScriptArgs()  # noqa: F821  (only defined inside Ghidra)
    export(currentProgram, _args[0])  # noqa: F821
except NameError:
    pass
