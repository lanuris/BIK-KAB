CC = g++
CFLAGS = -g
LDFLAGS = -lcrypto

all: solution
run:
	#run your tests here...
solution: solution.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)
