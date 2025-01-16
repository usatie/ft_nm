HELLO=hello
ABS=absolute_symbol.o

all: $(HELLO) $(ABS)

$(HELLO): hello.c
	$(CC) -o $(HELLO) hello.c

$(ABS): absolute_symbol.s
	$(CC) -c -o $(ABS) absolute_symbol.s

run: all
	./test.sh
