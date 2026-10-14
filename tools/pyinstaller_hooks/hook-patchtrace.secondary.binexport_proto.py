"""Make the upb C extension and the descriptor-pool modules explicit for the frozen BinExport2 loader.

binexport_proto imports protobuf lazily inside functions and refuses the pure-Python runtime. PyInstaller
6.22.3 collected `google._upb._message` without help in a Linux measurement (SPEC-10b §1), so this hook is a
guard against a silent pure-Python fallback (T4), not a fix. The build scripts' inventory check requires the
extension to be present.
"""
hiddenimports = ['google._upb._message', 'google.protobuf.descriptor_pb2', 'google.protobuf.descriptor_pool',
                 'google.protobuf.message_factory', 'google.protobuf.internal.api_implementation']
