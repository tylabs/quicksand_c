# QuickSand.io

QuickSand is a compact C framework to analyze suspected malware documents to 1) identify exploits in streams of different encodings, 2) locate and extract embedded executables. By having the ability to locate embedded obfuscated executables, QuickSand could detect documents that contain zero-day or unknown obfuscated exploits.


#### Office document malware analysis  
+cryptanalysis attack on 256 byte XOR obfuscation (2<sup>0-10</sup> bytes)  
+static extraction of embedded executables


QuickSand can be run as a command line tool, be wrapped in a web/db interface, or integrated into other products. It can be used as an exploit detection engine, a sandbox pre-processor, or a forensic tool to extract document malware streams. Fingerprint exploit kit usage by exploit location and offset. Run Yara malware trojan signatures on exploit documents against dynamically decoded streams and unXORed executables.


## Simple scoring:

*   is_malware=0: no known exploit, no obfuscated content, no embedded exe detected.
*   is_malware=1: no known exploit, dynamic content of undetermined threat, no embedded exe detected.
*   is_malware=2: exploit or embedded executable detected.
*   score=NN: detailed score based on Yara rule weighted scores.

## Features:

*   Fast document deconstruction
*   Yara API integration: Executable | Exploits | Trojans
*   Run yara signatures against decoded streams and unxored executables
*   Cryptanalysis of obfuscated executables and extraction: xor | rol/ror
*   Non bruteforce instant cracking of long 256 byte XOR keys (2<sup>0-10</sup> bytes).
*   Optional brute force 1 byte xor attack.
*   Optional brute force math cipher attack.
*   Optional xor-lookahead algorithm (xorla).
*   <u>Pre-sandbox processing of phishing samples to extract executables</u>/implant installers
*   Integratabtle cross platform Ansi C

### Sandbox pre-processing benefits:

*   Static extraction of embedded executables.
*   Less need for different versions of Office or PDF readers and patch levels in the sandbox environment.

### Exploit detection and embedded executable detection:

*   OLE MS Office documents: doc, xls, ppt...
*   RTF
*   MIME MSO/html MS Office format
*   OpenXML Docx, pptx, ppsx, xlsx...

### Embedded executable detection:

*   PDF
*   any other format such as Hangul Korean office documents

### Stream decoding:

*   Zip
*   Hex
*   Mime MSO/Base 64
*   ExOleObjStgCompressedAtom GZInflate
*   ActiveMime GZUncompress

## Static Library Dependencies:

*   [Yara](http://virustotal.github.io/yara/)
*   [libzip](http://www.nih.at/libzip/)
*   [zlib](http://www.zlib.net)

### Build from source:

*   ./build.sh

### Command line options:

Options:

*   -h or --help: this message
*   -j or --json: output json data
*   -b or --brute: brute force zero-not-replaced 1 byte xor
*   -l or --lookahead: try xor-lookahead algo
*   -m or --math: try math ciphers
*   -n or --not: try bitwise not
*   -e or --meanexec: [bytes] try chunking high entropy data
*   -s or --size: [len] try only xor keys of this size
*   -r or --raw: output proprietary text
*   -d or --drop: drop extracted executables
*   -o or --objects: drop all objects
*   -p or --out: [dir] directory to write dropped files
*   -y or --yara: skip yara scan for general / malware identification

### Industry standard Yara rules for known exploit detection:

Example rule, rank variable is used to score a sample.

rule warning_package_manager_embedded { meta: is_exploit = true is_warning = false is_feature = false rank = 1 revision = "1" date = "July 29 2015" copyright = "QuickSand.io (c) Copyright 2015\. All rights reserved." tlp = "green" desc = "Office package manager may load unsafe content such as shell scripts" strings: $s1 = "0003000C-0000-0000-c000-000000000046" nocase $s2 = "0c00030000000000c000000000000046" $s3 = {0c00030000000000c000000000000046} $s4 = "Packager Shell Object" ascii wide condition: 1 of them }

### C API:

<pre>#include "libqs.c"
quicksandInit(); //initialize system
struct qs_file *qs_root = NULL;

quicksand_do(string, fsize, quicksand_build_message("root", NULL, &qs_root, QS_FILE_CHILD), &qs_root);  //process string of size fsize
char *buffer = malloc(24000);
quicksandGraph(buffer, 24000, 0, qs_root); // create report
printf("%s", buffer); //print report
quicksandDropFiles(qs_root, &qs_root);
quicksandReset(&qs_root); //cleanup between samples
quicksandDestroy(); //final cleanup

</pre>


Copyright © 2015-2016 TyLabs. All rights reserved.
