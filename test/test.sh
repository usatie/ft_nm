#!/bin/bash -e
# hello
echo "./ft_nm hello"
diff <(../ft_nm hello) <(nm hello) && echo "OK" || echo "KO"
echo "./ft_nm hello.o"
diff <(../ft_nm hello.o) <(nm hello.o) && echo "OK" || echo "KO"
echo "./ft_nm hello_32_bit"
diff <(../ft_nm hello_32_bit) <(nm hello_32_bit) && echo "OK" || echo "KO"
echo "./ft_nm hello_32_bit.o"
diff <(../ft_nm hello_32_bit.o) <(nm hello_32_bit.o) && echo "OK" || echo "KO"

# weak_symbol
echo "./ft_nm weak_symbol"
diff <(../ft_nm weak_symbol) <(nm weak_symbol) && echo "OK" || echo "KO"
echo "./ft_nm weak_symbol.o"
diff <(../ft_nm weak_symbol.o) <(nm weak_symbol.o) && echo "OK" || echo "KO"
echo "./ft_nm weak_symbol_32_bit"
diff <(../ft_nm weak_symbol_32_bit) <(nm weak_symbol_32_bit) && echo "OK" || echo "KO"
echo "./ft_nm weak_symbol_32_bit.o"
diff <(../ft_nm weak_symbol_32_bit.o) <(nm weak_symbol_32_bit.o) && echo "OK" || echo "KO"

# absolute_symbol
echo "./ft_nm absolute_symbol.o"
diff <(../ft_nm absolute_symbol.o) <(nm absolute_symbol.o) && echo "OK" || echo "KO"
echo "./ft_nm absolute_symbol_32_bit.o"
diff <(../ft_nm absolute_symbol_32_bit.o) <(nm absolute_symbol_32_bit.o) && echo "OK" || echo "KO"

# ft_nm
echo "./ft_nm ft_nm"
diff <(../ft_nm ../ft_nm) <(nm ../ft_nm) && echo "OK" || echo "KO"
echo "./ft_nm src/main.o"
diff <(../ft_nm ../src/main.o) <(nm ../src/main.o) && echo "OK" || echo "KO"
echo "./ft_nm need_to_sort_dup_symbol"
diff <(../ft_nm need_to_sort_dup_symbol) <(nm need_to_sort_dup_symbol) && echo "OK" || echo "KO"
