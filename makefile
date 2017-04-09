# CC = g++
# CFLAGES = -lpcap
# CFLAGS = -c -std=c++11

# PROG1 = packetparse

# packetparse: $(PROG1).o
	# $(CC) $(CFLAGS) $(PROG1).o -o packetparse $(CFLAGES)

# $(PROG1).o: $(PROG1).cpp
	# $(CC) $(CFLAGS) $(PROG1).cpp

all: packetparse.cpp
	g++ -std=c++11 -o packetparse packetparse.cpp -lpcap

clean:
		rm -rf *o packetparse


