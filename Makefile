exe:
	clang ./tests/test.c -o test
	clang++ -g -std=c++2b -o wallace ./src/*.cpp

clean:
	rm ./test
	rm ./wallace
