LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH
gcc -o quicksand.out quicksand.c  -L/usr/local/lib -lyara -lzip -lz
