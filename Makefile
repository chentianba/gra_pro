CC = clang
all: main.o bloom_filter.o cuckoo_filter.o
	${CC} -o main main.o bloom_filter.o cuckoo_filter.o
main.o: main.c bloom_filter.h
	${CC} -c main.c bloom_filter.h
bloom_filter.o: bloom_filter.c bloom_filter.h
	${CC} -c bloom_filter.c bloom_filter.h
cuckoo_filter.o: cuckoo_filter.c cuckoo_filter.h
	${CC} -c cuckoo_filter.c cuckoo_filter.h
clean:
	rm -f main main.o bloom_filter.o
