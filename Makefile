APP_NAME := arakne
BUILD_DIR := build
CMD_PATH := cmd/arakne/main.go

.PHONY: all clean windows linux macos

all: clean windows linux macos

init:
	go mod tidy

windows:
	@echo "Building for Windows (Heavy Artillery)..."
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME).exe $(CMD_PATH)

linux:
	@echo "Building for Linux (The Hunter - Static)..."
	# CGO_ENABLED=0 for static binary, but 1 needed for some advanced linking later.
	# For now, pure Go + eBPF loading logic.
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)_linux $(CMD_PATH)

macos:
	@echo "Building for macOS (The Gatekeeper)..."
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)_mac_arm64 $(CMD_PATH)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)_mac_amd64 $(CMD_PATH)

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
