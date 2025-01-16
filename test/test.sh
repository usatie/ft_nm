#!/bin/bash -e
echo "./ft_nm hello"
diff <(../ft_nm hello) <(nm hello) && echo "OK" || echo "KO"
echo "./ft_nm absolute_symbol.o"
diff <(../ft_nm absolute_symbol.o) <(nm absolute_symbol.o) && echo "OK" || echo "KO"
echo "./ft_nm ft_nm"
diff <(../ft_nm ../ft_nm) <(nm ../ft_nm) && echo "OK" || echo "KO"
echo "./ft_nm src/main.o"
diff <(../ft_nm ../src/main.o) <(nm ../src/main.o) && echo "OK" || echo "KO"
