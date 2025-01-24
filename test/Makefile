HELLO=hello
HELLO_32_bit=hello_32_bit
ABS=absolute_symbol.o

all: $(HELLO) $(HELLO_32_bit) $(ABS)

hello.o: hello.c
	$(CC) -c -o hello.o hello.c

hello_32_bit.o: hello.c
	$(CC) -m32 -c -o hello_32_bit.o hello.c

$(HELLO): hello.o
	$(CC) -o $(HELLO) hello.o

$(HELLO_32_bit): hello_32_bit.o
	$(CC) -m32 -o $(HELLO_32_bit) hello_32_bit.o

$(ABS): absolute_symbol.s
	$(CC) -c -o $(ABS) absolute_symbol.s

run: all
	./test.sh
