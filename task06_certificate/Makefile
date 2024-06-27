CC = gcc
CFLAGS = -g
LDFLAGS = -lssl -lcrypto

all: solution
run:
	#run your tests here...
solution: solution.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
