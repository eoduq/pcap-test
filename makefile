LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o set_headers.o print.o
pcap-test.o: header_structures.h pcap-test.c
set_headers.o: header_structures.h set_headers.h set_headers.c
print.o: print.h print.c header_structures.h
clean:
	rm -f pcap-test *.o
