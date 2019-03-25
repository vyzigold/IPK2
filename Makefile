.PHONY: all clean

all: ipk-scan

ipk-scan: scan.o
	g++ scan.o -g -o ipk-scan -lpcap

scan.o: scan.c
	g++ -c -g scan.c -g -o scan.o

clean:
	-rm -f ipk-scan
	-rm -f scan.o
