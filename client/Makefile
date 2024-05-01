CC=g++
CFLAGS=-Wall -Wextra -ansi -pedantic -lcrypto -std=c++17 -lstdc++fs
SOURCES=client.cpp authentication.cpp ../common/utils.cpp ../common/errors.cpp ../common/dhparams.cpp  ../common/seq.cpp actions/logout.cpp actions/list.cpp actions/rename.cpp actions/download.cpp actions/delete.cpp actions/upload.cpp
OBJECTS=$(SOURCES:.cpp=.o)
BINARY=client

# Debug build flags. Use `make DEBUG=1` to build in debug mode.
# Defaults to zero (i.e. release)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG -g -ldl -export-dynamic
else
    CFLAGS += -DNDEBUG -O3
endif

.PHONY : clean

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BINARY) $(OBJECTS)
