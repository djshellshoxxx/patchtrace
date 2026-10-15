Install an offline backend bundle
Experimental: the offline ZIP installer is documented and tested with synthetic packages. The reviewed offline guide states that an official, fully tested complete backend archive has not been published. Availability of an approved archive for your release is UNVERIFIED.
The desktop ZIP alone does not provide Ghidra, Java, and Ghidriff. A backend bundle must contain a complete, compatible, relocatable runtime.
When an approved bundle is available:
1. Transfer the desktop package, backend ZIP, trusted archive checksum, and notices to the target computer.
2. Open Setup.
3. Enter the independently obtained checksum in Trusted offline ZIP checksum. The field accepts 64 lowercase hexadecimal characters.
4. Select Install offline backend ZIP… and choose the local archive.
5. Review the runtime identity and full archive hash before confirming installation.
6. Wait for completion.
7. Check the populated Python, Ghidra, and private Java paths.
8. Select Diagnose dependencies, then Save setup.
9. Compare a known compatible binary pair.
The checksum field is optional in the documented interface. Supplying an independently trusted value binds the selected archive to that value. Internal inventory hashes establish file agreement, not publisher identity.
Installation verifies and extracts files without executing the payload or downloading dependencies. Failed or cancelled installation preserves existing installations and projects.
Disconnected Windows acceptance, native execution, and network isolation require separate checks. Disabling symbol lookup alone does not create an air gap.
Sources: docs/offline-backend.md; docs/windows.md; src/patchtrace/tooltips.py.
