# DIY pinter

I found some source code for a do-it-yourself flag printer but it looks like it only builds using this weird cmake source. I tried everything I could think of, i.e.

mkdir build
cd build
cmake ..
but it didn’t work :( I never understood that build system stuff so can you please help me out?

(You should be able to safely ignore the *.h and *.c files — they are just to print the flag when you succeed.)

**Total solves:** 16

**Score:** 400

**Categories:** Miscellaneous, Reversing

## CMake Source

The CMakeLists.txt employs a VM on cmake and its VM code is in the file. The VM code is interpreted and executed before the C project is built. This project is only built if the string in `password.txt` file is correct.

All cmake source code variable names were obfuscated. All of the source code was analyzed to understand how the VM operates and, after the analysis, the [source code](CMakeLists.txt) had all its variables renamed and we built a Python script to simulate the VM employed on cmake. This [script](vm.py) was used to run some tests and to understand the code executed by the VM.

## Solution

The VM code implemented on Python was reused to find out the expected string using Z3. However, there was a caveat while executing function `V()`. As the function seems to execute integer division between its arguments, its code was properly updated and the [solve.py](script) worked.

Running the script returns the expected password to build the C project: `>@PJ(2{i2up8xmZe`. This string was put in `password.txt` file, the cmake build commands worked and we got the flag.

Flag: hxp{cm4k3\_1s\_h4rd3r\_7h4n\_n4t1v3}
