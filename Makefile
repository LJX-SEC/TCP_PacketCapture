PCAP: PCAP.c
	gcc -o ./PCAP ./PCAP.c	-lpcap

clean:
	rm -rf ./PCAP