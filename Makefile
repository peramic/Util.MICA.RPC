CFLAGS=-O3 -Wall -fmessage-length=0 -fPIC -MMD -MP
LDFLAGS=-lwebsockets -lssl -lcrypto
SOURCES=src/mica_rpc.c
TARGET=mica-rpc
OBJS=$(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET) src/*.d