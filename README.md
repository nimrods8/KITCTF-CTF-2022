# KITCTF-CTF-2022
Koeri Factory [PWN]<br><br>
![](https://github.com/nimrods8/KITCTF-CTF-2022/blob/main/koeri1.png?raw=true)

So, first thing's first... We noticed the name "koeri" or "kœri" and wondered what is it?<br>
It seems like Kœri is a kind of German(?) dish:
![](https://github.com/nimrods8/KITCTF-CTF-2022/blob/main/5053_koeriwerk_galerie3.jpg)
And there are some [jokes](https://www.urbandictionary.com/define.php?term=%5Bk%C5%93ri%5D) about it also, coming from the Karlsruhe Institutde of Technology, where this CTF is originating from...
<br><br>
Now to the challenge:<br><br>
*(1) Code Analysis*<br>
We start with `main.c`:

```
[...redacted...]
#define ALARM_SECONDS 10

void be_a_ctf_challenge() {
    alarm(ALARM_SECONDS);
}

int main() {
    be_a_ctf_challenge();
    puts("Okay, since you are in here, you can take a look at it. But no photos!");
    setvbuf(stdout,(char *)0x0,2,1);
    char buffer[100];
    int fd = open("./flag.txt", O_RDONLY);
    if (fd < 0) {
        perror("Could not open flag file");
        exit(-1);
    }
    printf("The kœri is safely(?) stored in fd %d\n", fd);
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    ADD_SECCOMP_RULE(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read      ), 0);
    if(seccomp_load(ctx) < 0) {
        perror("Could not load seccomp context! This is not your fault. The challenge is broken.");
        exit(-1);
    }
    read(0, buffer, 0x1000);
}
```
<br><br>
The main function is setting up a timeout of 10 seconds. This is the time frame we have until the server side exits.
Then, allocates 100 bytes for `buf` on the stack, opens the flag.txt file, reports to the client the file descriptor (fd) of the opened file and sets the sandbox using `seccomp`: all syscalls are banned but the `read` syscall!<br><br>
At the bottom `main` is reading from `stdin` upto 0x1000 bytes. 
<br>
*This is clearly a stack overflow waiting to happen!*  
  
*(2) We have a stack overflow, can we exploit it?*

In order to answer that question we need to look at how `main.c` is built.

We were given the `Makefile` of `main.c`, and here is what it does:

```
gcc main.c -o main -lseccomp -fno-stack-protector -z execstack -no-pie
```

These gcc flags are important:  
**no-stack-protector** flag removes stack [canaries](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/), an important anti-stack-smashing protection. 

**execstack** flag allows code to run on the stack (this marks the stack memory region as `x` or executable).

**no-pie** flag tells gcc that the output should not be position independent (Position Independent Execution). For our purposes, this means that all the code that goes with the `main` ELF will always be loaded to the same addresses in memory and the Linux loader will not be able to randomize its addresses. It does *not* mean that libraries (.so files) will be loaded into non-randomized addresses...
  
To summarize: these flags tell us two things -   
- The server's stack is, intentionally, made exploitable, and  
- The ELF code addresses are intentionally made constant, regardless of ASLR.  
  
  
    
*(3) Stack overflow exploitation - step 1*  
We begin by analyzing the `main` stack just before it is returning:  
![](https://github.com/nimrods8/KITCTF-CTF-2022/blob/main/koeri_atret.png)   

Just before executing the `ret` instruction the `rsp` (marked in a yellow rectangle) would be pointing to the return address at *7fffffffe458* (marked in red).  
The `rsi` points to the beginning of `buffer`.  
So, if we count the bytes from `rsi`, i.e. *7fffffffe340* to the return address at *7fffffffe458* we get the number of bytes we should fill in order to be able to control the return address of the code, or a code execution primitive. This equals **0x88 bytes**.  
To summarize, now know how many bytes we need to fill in order to gain a code execution primitive (which is 0x88) and we can also see that this is feasible as far as the `read` is concerned, which would willingly read upto 0x1000 bytes...  
  
  
*(4) Stack overflow exploitation - step 2*  
Now that we know how to gain code execution on the server we should come up with what to write there.  
We have a number of options:  
- If the server has completely disabled ASLR, then we can probably write a static stack address and by doing that point the execution of the server to another area of the stack. We can do that because the stack was marked executable.
- If ASLR is still on then it would be quite difficult to guess the randomized stack address, in order to divert execution to the stack. In this case, we may be able to take advantage of the address already coded in the return address (*7ffff7d86d90* in this gdb case) and perhaps return there...
- Find another address already in the stack that we can slightly change to cause a beneficial code execution to us.  

 



