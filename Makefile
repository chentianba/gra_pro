CC = clang
INCLUDE_DIRS = include/
CCFLAGS = -I $(INCLUDE_DIRS) -Wall
OBJ_DIR = obj
SRC_DIR = src
TARGET = main

SRCS = $(foreach dir, $(SRC_DIR), $(wildcard $(dir)/*.c))
OBJS = $(addprefix $(OBJ_DIR)/, $(patsubst %.c, %.o, $(notdir $(SRCS))))

$(TARGET): $(OBJS)
	$(CC) -o $@ $^
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi;
	$(CC) $(CCFLAGS) -c $^ -o $@
clean:
	rm -rf main $(OBJ_DIR)
