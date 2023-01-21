#!/bin/bash

echo "Copy dynamic libraries to /usr/lib for some tests"
sudo cp "libtest.so" "/usr/lib/libtest.so"
sudo cp "libtest2.so" "/usr/lib/libtest2.so"
sudo cp "libtest3.so" "/usr/lib/libtest3.so"
echo "Start testing..."
gcc -std=c99 *.c -o prf
if [ -f "prf" ]; then
    params=("NULL"	"foo"	"foo"	"bar"	"rec_bar"	"lib_foo"	"rec_lib_foo"	"tutit"	"foo"	"lib_foo"	"lib_foo"	"rec_foo"	"rec_bar"\
    		"food"	"food"	"food"	"foo"	"foo")
	for i in {1..10}
	do
		timeout 20s ./prf $(echo ${params[$i]}) "program${i}.out" > studentout.txt
		if [ $? -eq 0 ]; then
			diff "out${i}.txt" studentout.txt
			if [ $? -eq 0 ]; then
				echo -e "Test${i} (7pts):\t\tPASS"
			else
				echo -e "Test${i} (7pts):\t\tFAIL - diff"
			fi
		else
			echo -e "Test${i} (7pts):\t\tFAIL - Infinite loop / Exit status error"
		fi
	done
	for i in {11..12}
	do
		timeout 20s ./prf $(echo ${params[$i]}) "program${i}.out" > studentout.txt
		if [ $? -eq 0 ]; then
			diff "out${i}.txt" studentout.txt
			if [ $? -eq 0 ]; then
				echo -e "Test${i} (3pts):\t\tPASS"
			else
				echo -e "Test${i} (3pts):\t\tFAIL - diff"
			fi
		else
			echo -e "Test${i} (3pts):\t\tFAIL - Infinite loop / Exit status error"
		fi
	done
	for i in 13
	do
		timeout 20s ./prf $(echo ${params[$i]}) "program${i}.out" > studentout.txt
		if [ $? -eq 0 ]; then
			diff "out${i}.txt" studentout.txt
			if [ $? -eq 0 ]; then
				echo -e "Test${i} (4pts):\t\tPASS"
			else
				echo -e "Test${i} (4pts):\t\tFAIL - diff"
			fi
		else
			echo -e "Test${i} (4pts):\t\tFAIL - Infinite loop / Exit status error"
		fi
	done
	for i in {14..17}
	do
		timeout 20s ./prf $(echo ${params[$i]}) "program${i}.out" > studentout.txt
		if [ $? -eq 0 ]; then
			diff "out${i}.txt" studentout.txt
			if [ $? -eq 0 ]; then
				echo -e "Test${i} (5pts):\t\tPASS"
			else
				echo -e "Test${i} (5pts):\t\tFAIL - diff"
			fi
		else
			echo -e "Test${i} (5pts):\t\tFAIL - Infinite loop / Exit status error"
		fi
	done
	timeout 20s ./prf "foo" "program_arg.out" "RUNNNN" > studentout.txt
	if [ $? -eq 0 ]; then
		diff "out_arg.txt" studentout.txt
		if [ $? -eq 0 ]; then
			echo -e "Bonus Test 1 (4pts):\tPASS"
		else
			echo -e "Bonus Test 1 (4pts):\tFAIL - diff"
		fi
	else
		echo -e "Bonus Test 1 (4pts):\tFAIL - Infinite loop / Exit status error"
	fi
	timeout 20s ./prf "foo" "glob_loc.out" > studentout.txt
	if [ $? -eq 0 ]; then
		diff "out_glob_loc.txt" studentout.txt
		if [ $? -eq 0 ]; then
			echo -e "Bonus Test 2 (4pts):\tPASS"
		else
			echo -e "Bonus Test 2 (4pts):\tFAIL - diff"
		fi
	else
		echo -e "Bonus Test 2 (4pts):\tFAIL - Infinite loop / Exit status error"
	fi
else
	echo -e "Compilation error - prf not found"
fi
sudo rm -f "./prf"
echo "END OF TEST"
