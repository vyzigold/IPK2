.PHONY: all clean

all: ipk-scan

ipk-scan: scan.o ipv4.o common.o ipv6.o
	g++ scan.o ipv4.o ipv6.o common.o -g --std=c++11 -o ipk-scan -lpcap

scan.o: scan.c
	g++ -c -g scan.c --std=c++11 -g -o scan.o

ipv4.o: ipv4.cxx
	g++ -c -g ipv4.cxx --std=c++11 -g -o ipv4.o

ipv6.o: ipv6.cxx
	g++ -c -g ipv6.cxx --std=c++11 -g -o ipv6.o

common.o: common.cxx
	g++ -c -g common.cxx --std=c++11 -g -o common.o

clean:
	-rm -f ipk-scan
	-rm -f scan.o
	-rm -f common.o
	-rm -f ipv4.o
	-rm -f ipv6.o
