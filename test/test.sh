#!/bin/bash

test_nm() {
	echo "-------------------------"
	echo "Testing: ft_nm $@"

	# ft_nm: Get output and return code
	ft_output=$(../ft_nm "$@" 2>&1)
	ft_ret=$?

	# nm: Get output and return code
	nm_output=$(nm "$@" 2>&1)
	nm_ret=$?

	# Compare outputs and return codes
	if [[ "$ft_output" == "$nm_output" && $ft_ret -eq $nm_ret ]]; then
		echo "OK"
	else
		echo "KO"
		if [[ "$ft_output" != "$nm_output" ]]; then
			echo "========== diff =========="
			diff <(echo "$ft_output") <(echo "$nm_output")
		elif [[ $ft_ret -ne $nm_ret ]]; then
			echo "========= status ========="
			echo "ft_nm exit status: $ft_ret"
			echo "nm    exit status: $nm_ret"
		fi
		echo "=========================="
	fi
}

# 64-bit ELF
test_nm hello
test_nm hello.o

# 32-bit ELF
test_nm hello_32_bit
test_nm hello_32_bit.o

# Weak symbols
test_nm weak_symbol
test_nm weak_symbol.o
test_nm weak_symbol_32_bit
test_nm weak_symbol_32_bit.o

# Absolute symbols
test_nm absolute_symbol.o
test_nm absolute_symbol_32_bit.o

# Actual files
test_nm ../ft_nm
test_nm ../src/main.o

# Duplicated symbols
test_nm need_to_sort_dup_symbol

# Multiple files
test_nm hello.o hello weak_symbol absolute_symbol.o

# Invalid files
test_nm no_such_file
test_nm hello.o no_such_file weak_symbol

# Dynamic Libraries (on AWS EC2 Ubuntu)
# test_nm /usr/lib/modules/6.8.0-1021-aws/vdso/vdso64.so
# test_nm /usr/lib/modules/6.8.0-1021-aws/vdso/vdso32.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/32/libubsan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/32/libasan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/x32/libubsan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/x32/libasan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/libubsan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/libtsan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/libasan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/libhwasan.so
# test_nm /usr/lib/gcc/x86_64-linux-gnu/13/liblsan.so
# test_nm /usr/lib/linux-tools/6.8.0-1021-aws/libperf-jvmti.so
# test_nm /usr/lib/linux-aws-tools-6.8.0-1021/libperf-jvmti.so

