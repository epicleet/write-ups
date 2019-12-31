CXXFLAGS = -Wall -Werror -fopenmp -Ofast -march=native
LIBS = -lbsd
all: brute meet
%: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)
clean:
	rm -f brute
