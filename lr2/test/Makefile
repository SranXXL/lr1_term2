test1_gcc: 
	gcc -o test1 test1.c

test2_gcc: 
	gcc -o test2 test2.c

clean:
	rm ./test_file_copy.txt	

check:
	sudo chmod 777 ./test_file_copy.txt
	md5sum test_file.txt
	md5sum test_file_copy.txt

