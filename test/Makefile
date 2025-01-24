ABS=absolute_symbol.o

all:
	# hello
	$(CC) -c -o hello.o hello.c
	$(CC) -m32 -c -o hello_32_bit.o hello.c
	$(CC) -o hello hello.o
	$(CC) -m32 -o hello_32_bit hello_32_bit.o

	# weak_symbol
	$(CC) -c -o weak_symbol.o weak_symbol.c
	$(CC) -m32 -c -o weak_symbol_32_bit.o weak_symbol.c
	$(CC) -o weak_symbol weak_symbol.o
	$(CC) -m32 -o weak_symbol_32_bit weak_symbol_32_bit.o

	# absolute_symbol
	$(CC) -c -o absolute_symbol.o absolute_symbol.s
	$(CC) -m32 -c -o absolute_symbol_32_bit.o absolute_symbol.s

run: all
	./test.sh
