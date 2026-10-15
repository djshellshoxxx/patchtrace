"""Adapters that implement the `rules.ports` Protocols over the rest of PatchTrace (YRX-integration-plan section 7).

`tools_delta` (strings from the FLOSS delta, capabilities from the capa delta) and `pe_imports` (import tables from
`pe_overview`) are pure and Qt-free; `mask_iced` is the only adapter that imports the decoder extension. The core of
`rules` never imports an adapter: it is handed one through a port.
"""
