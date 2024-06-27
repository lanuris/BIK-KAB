CC = g++
CFLAGS = -g
LDFLAGS = -lcrypto

all: solution
run:
	#run your tests here...
solution: sample.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)
