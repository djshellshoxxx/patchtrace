"""DiE record-type vocabulary (pure data, no process or Qt imports) shared by the diec parser and `delta`."""
from __future__ import annotations

# The 57 RECORD_TYPE names of XScanEngine (lower case, as scripts emit them) -> normalised category; the raw name
# is always kept on the evidence. Anything else is `other` and counted as vocabulary drift.
TYPE_CATEGORY = {
    'unknown': 'unknown', 'apk obfuscator': 'other', 'apk tool': 'other', 'archive': 'archive', 'author': 'other',
    'certificate': 'other', 'compiler': 'compiler', 'compressor': 'packer', 'converter': 'other',
    'corrupted data': 'other', 'creator': 'other', 'crypter': 'cryptor', 'cryptor': 'cryptor', 'data': 'other',
    'database': 'other', 'debug data': 'other', 'document': 'other', 'dongle protection': 'other',
    'dos extender': 'other', 'format': 'format', 'generic': 'other', 'image': 'other', 'installer': 'installer',
    'installer data': 'installer', 'jar obfuscator': 'other', 'joiner': 'other', 'language': 'language',
    'library': 'library', 'licensing': 'other', 'linker': 'linker', 'loader': 'other', 'malware': 'other',
    '.net compressor': 'packer', '.net obfuscator': 'protector', 'obfuscator': 'protector',
    'operation system': 'os', 'overlay': 'overlay', 'package': 'other', 'packer': 'packer', 'personal data': 'other',
    'pe tool': 'petool', 'platform': 'other', 'player': 'other', 'producer': 'other', 'protection': 'protector',
    'protector': 'protector', 'protector data': 'other', 'rom': 'other', 'sfx': 'sfx', 'sfx data': 'sfx',
    'sign tool': 'signtool', 'source code': 'other', 'stub': 'other', 'tool': 'tool', 'trojan': 'other',
    'virtual machine': 'other', 'virus': 'other'}
# Warning sets shared with `delta.quality_flags`; every table name is in exactly one set or is listed as neutral.
PACKED_TYPES = frozenset({'packer', 'compressor', '.net compressor', 'cryptor', 'crypter'})
PROTECTED_TYPES = frozenset({'protector', 'protection', 'obfuscator', '.net obfuscator'})
INSTALLER_TYPES = frozenset({'installer', 'installer data', 'sfx', 'sfx data'})
NEUTRAL_TYPES = frozenset({
    'unknown', 'apk obfuscator', 'apk tool', 'archive', 'author', 'certificate', 'compiler', 'converter',
    'corrupted data', 'creator', 'data', 'database', 'debug data', 'document', 'dongle protection', 'dos extender',
    'format', 'generic', 'image', 'jar obfuscator', 'joiner', 'language', 'library', 'licensing', 'linker', 'loader',
    'malware', 'operation system', 'overlay', 'package', 'personal data', 'pe tool', 'platform', 'player',
    'producer', 'protector data', 'rom', 'sign tool', 'source code', 'stub', 'tool', 'trojan', 'virtual machine',
    'virus'})
