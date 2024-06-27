CC = g++
CFLAGS = -g
LDFLAGS = -lcrypto

all: sample
run:
	#run your tests here...
sample: sample.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)
