# Third-party components

The MIT license in LICENSE covers AOSEye project code, not third-party software.
This file is an inventory guide, not a replacement for dependency license texts.

AOSEye declares PySide6, PyYAML, defusedxml and cryptography as runtime dependencies.
Their transitive dependencies, native libraries and applicable license texts must
be reviewed for the exact versions distributed. Pip installs dependencies separately;
the AOSEye wheel does not vendor them. Retain the notices shipped in each installed
distribution. Do not assume AOSEye's MIT license covers Qt or these dependencies.

JEB is a separately licensed proprietary prerequisite. AOSEye does not distribute
JEB binaries, JARs, license files or a license bypass. Users must install an edition
that permits the required Core API operations and explicitly supply its path.
Java and optional Android SDK tools are separately installed prerequisites as well.

User APKs, application assets and generated decompilations are not licensed by
AOSEye. Do not redistribute test subjects or saved analysis projects without the
necessary permission. Synthetic fixture sources are included; generated APK/DEX
files are excluded from the source distribution.

Before bundling dependencies in an executable/offline installer, perform a new
license and notice review. A successful wheel install does not approve redistribution.
