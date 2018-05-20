all: cuckoo_filter.o bloom_filter.o main.o
	gcc -o main main.o cuckoo_filter.o bloom_filter.o
cuckoo_filter.o:cuckoo_filter.c
	gcc -c cuckoo_filter.c
bloom_filter.o:bloom_filter.c
	gcc -c bloom_filter.c
main.o:main.c
	gcc -c main.c
clean:
	rm -f *.o
