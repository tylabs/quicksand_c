QuickSand.io CLI 








QuickSand is a compact C framework to analyze suspected malware documents to 1) identify exploits in streams of different encodings, 2) locate and extract embedded executables. By having the ability to locate embedded obfuscated executables, QuickSand could detect documents that contain zero-day or unknown obfuscated exploits.


Dependencies
libyara Yara 3.4+ (requires gcc automake libtool openssl) http://virustotal.github.io/yara/
libzip http://www.nih.at/libzip/
zlib http://www.zlib.net

You can use the quicksand_dependencies.txt script to download and install the dependancies.



Building
./build.sh


Simple scoring:

*   is_malware=0: no known exploit, no obfuscated content, no embedded exe detected.
*   is_malware=1: no known exploit, dynamic content of undetermined threat, no embedded exe detected.
*   is_malware=2: exploit or embedded executable detected.
  score=NN: detailed score based on Yara rule weighted scores.


Command line options:

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