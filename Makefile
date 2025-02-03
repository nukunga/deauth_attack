# Makefile for Deauth and Auth Attack

CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -lpcap

# 소스 파일
SRC = main.cpp deauth.cpp auth.cpp
# 출력 실행 파일
TARGET = deauth-attack

# Make 명령어로 실행할 때 컴파일 및 링크 작업
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# 클린업 명령어
clean:
	rm -f $(TARGET)

# 사용법 출력
usage:
	@echo "Usage: make [clean|usage]"
