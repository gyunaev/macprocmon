OBJ=EndpointSecurity.o main.o
CFLAGS=-Wall -std=c++14

all: $(OBJ)
	g++ $(OBJ) -l EndpointSecurity -framework Foundation -l bsm -o proctracer
	codesign --entitlements proctracer.entitlements --force -s - proctracer

%.o: %.cpp
	g++ $(CFLAGS) -c $<
