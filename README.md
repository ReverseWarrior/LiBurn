# LiBurn

Developed by Liel.

LiBurn is a utility that enables you to combine two Windows executables into a single portable executable (PE) file, seamlessly combining their functionality.

## Overview

LiBurn simplifies the process of embedding the functionality of one executable (the payload) into another, creating a unified executable file. This tool is particularly useful for developers and security researchers looking to modify or enhance existing PE files.

## Instructions

1. **Compile the Program**: Run the `build.bat` script to compile LiBurn. Ensure you have cmake, ninja and donut.
2. **Use LiBurn**: Execute `LiBurn.exe` with the path to the target PE file where you want to embed your payload. For example:
```
./LiBurn <path-to-target-PE>
```
Which will combine the functionality of your payload into the specified PE file.
