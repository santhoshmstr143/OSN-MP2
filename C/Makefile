CC = gcc
CFLAGS = -Wall -pthread -g
TARGET = bakery

all: $(TARGET)

$(TARGET): bakery.c
	$(CC) $(CFLAGS) -o $(TARGET) bakery.c

clean:
	rm -f $(TARGET)

.PHONY: all clean