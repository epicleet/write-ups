#### Nome

Accessing the Truth

#### PT-BR

Laura está tentando acessar a máquina de monitoramento. Ela será capaz de fazer
o que é necessário para ver a verdade?

#### EN

Laura is trying to access the monitoring machine. Will she be able to do what
is needed to see the truth?

#### Flag

CTF-BR{pwning_the_bios_is_expected...dont_tell_me_you_solved_unitended}

#### Hints

This challenge is about the BIOS firmware. Here is a better way than netcat to
interact with the server: 'socat STDIO,icanon=0,echo=0 TCP4:$IP:$PORT,crnl'.
