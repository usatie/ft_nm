#!/bin/bash -x
diff <(../ft_nm hello) <(nm hello)
diff <(../ft_nm absolute_symbol.o) <(nm absolute_symbol.o)
diff <(../ft_nm ../ft_nm) <(nm ../ft_nm)
diff <(../ft_nm ../src/main.o) <(nm ../src/main.o)
