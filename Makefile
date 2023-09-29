INC_DIR = ./inc
SRC_DIR = ./src
BUILD_DIR = ./build

CC=gcc
# -Wall -Wextra 
FLAGS = -pthread -g -I$(INC_DIR)
# FLAGS += -DTCP_DEBUG
OBJS = $(BUILD_DIR)/x_packet.o $(BUILD_DIR)/x_tcp.o 

default:all

all: clean server client

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | create_build_dir
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)

client:
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS) 

create_build_dir:
	mkdir -p $(BUILD_DIR)

clean:
	-rm -rf ./build/ client server
