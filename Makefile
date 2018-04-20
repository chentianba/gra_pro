CC = clang
all: main.o algorithm.o
	${CC} -o main main.o algorithm.o
main.o: main.c algorithm.h
	${CC} -c main.c algorithm.h
algorithm.o: algorithm.c algorithm.h
	${CC} -c algorithm.c algorithm.h
clean:
	rm -f main main.o algorithm.o
