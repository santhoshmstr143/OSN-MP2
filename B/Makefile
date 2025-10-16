CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

TARGET = cshark
SRCS = main.c utils.c storage.c packet_handler.c filter.c inspect.c interface.c
OBJS = $(SRCS:.c=.o)
HEADER = cshark.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean