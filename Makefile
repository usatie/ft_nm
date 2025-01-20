NAME=ft_nm
CC=cc
CFLAGS=-Wall -Werror -Wextra
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:%.c=%.o)
INC=-I./include

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INC)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

dbuild:
	docker buildx build --platform=linux/amd64 -t amd64-ft-nm .

drun:
	docker run --rm -it --platform=linux/amd64 amd64-ft-nm bash

test: all
	$(MAKE) run -C test
