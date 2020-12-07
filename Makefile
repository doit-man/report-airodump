all: airodump
	
airodump: main.o
	g++ -o airodump main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -r airodump *.o
