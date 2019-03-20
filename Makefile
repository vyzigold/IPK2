.PHONY: all clean

all: ipk-scan

ipk-scan: scan.o
	g++ scan.o -o ipk-scan -lpcap

scan.o: scan.c
	g++ -c -g scan.c -o scan.o

clean:
	-rm -f ipk-scan
	-rm -f scan.o
