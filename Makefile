NAME=ft_nm
CC=cc
CFLAGS=-Wall -Werror -Wextra
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:%.c=%.o)
INC=-I./include -I./libft/include
LIBFT=libft/libft.a

all: $(NAME)

$(NAME): $(LIBFT) $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS) $(LIBFT)

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

$(LIBFT):
	$(MAKE) -C libft

.PHONY: all clean fclean re dbuild drun test
