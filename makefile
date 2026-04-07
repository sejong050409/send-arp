all: send-arp

send-arp: main.cpp ethernet.h arp.h headers.h
	g++ -o send-arp main.cpp -lpcap

clean:
	rm -f send-arp
