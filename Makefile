# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -g -O3
LDFLAGS = -lvmi -lyara

# Directories
BIN_DIR = bin
OBJ_DIR = obj

# Source files, object files, and target
SRCS = main.cpp scan_memory.cpp
OBJS = $(patsubst %.cpp, $(OBJ_DIR)/%.o, $(SRCS))
TARGET = scan_memory

# Default target
all: $(BIN_DIR)/$(TARGET)

# Build the target in the bin directory
$(BIN_DIR)/$(TARGET): $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Compile source files into the obj directory
$(OBJ_DIR)/%.o: %.cpp
	mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Phony targets
.PHONY: all clean
