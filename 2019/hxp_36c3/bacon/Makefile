CXXFLAGS = -Wall -Werror -fopenmp -Ofast -march=native
LIBS = -lbsd
brute: brute.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)
clean:
	rm -f brute
