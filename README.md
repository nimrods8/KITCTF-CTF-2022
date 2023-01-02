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

 
*(a) Testing for Static Stack Addresses*
gdb is, by default, disabling ASLR, so we can see the static stack addresses there.
By running `info proc mappings` we get:
`0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rwxp   [stack]`  
  
So, the stack starts at 0x7fffffffde000, is executable and ends 21,000 hex bytes later. The address of `buffer` on the stack, as we could see in our gdb, was *7fffffffe3d0*, but this address may be different on the server (due to different environment variables, for example).
So we decided to try and (gently) "brute-force" the lower 2 bytes of the stack address and see if we get a favorable response from the server...  
But what's a favorable response?  
We know the server is using `socat` to wait for an incoming TCP connection and then run `main`.  
`main` is then reading information from `stdin` and writes it to `buffer`. We can tell when `main` stops executing if we look at the TCP connection, for example, using *Wireshark*:  

![](https://github.com/nimrods8/KITCTF-CTF-2022/blob/main/Capture1.PNG)  

The server sends a FIN packet when `main` stops execution. This is because `socat` signals the client that it cannot send anymore packets (by sending FIN), however, `socat` is still receiving, even though `main` has stopped.  
  
By sending the following code bytes to the server we are able to check if we can run code using stack addresses:
  
```  
0:  90                      nop
1:  90                      nop
2:  90                      nop
...
...
12a:  90                      nop
12b:  48 c7 c0 ce 13 40 00    mov    rax,0x4013ce
132:  ff e0                   jmp    rax
134:  90                      nop
135:  90                      nop
136:  90                      nop
137:  xx xx ff ff ff 7f 00 00      # return address
```  

Just replace the `xx xx` with addresses...  
Notice that we are using an absolute jump to 0x4013ce. This is something we can do because `main` was compiled with **no-pie**.

Trying some of the combinations yielded nothing, so we had to go back to the drawing board and concluded that `ASLR` is still on in the target server.
  
  
*(b) Attempting to jump to libc using ROP gadgets*  
Failing to locate the address of the stack we now look at what we have already present in the return address on the stack, and check if we can use that to gain code execution.  
The `main` original return address is *7ffff7d86d90*.  So, we turn back to gdb's `info proc mappings` to find what is it?  
  
`0x7ffff7d85000     0x7ffff7f1a000   0x195000    0x28000  r-xp   /usr/lib/x86_64-linux-gnu/libc.so.6`  
  
It seems that the `main`'s original return address points inside libc. That's great, so maybe we can run some [ROP gadgets](https://en.wikipedia.org/wiki/Return-oriented_programming) and get a stable code execution on the server!  
  
Looking back at the gdb screenshot, we can see that RSI contains the address of `buffer`, and we can write into `buffer`! So if we can somehow find a gadget that runs `jmp rsi` (opcode `ffe6`) or `call rsi` (opcode `ffd6`), we'll be running code on the server!  
  
When looking into ROP gadgets there is always the question of which version of `libc` is being used on the server. In our case, this question is promptly answered by Docker... Looking into the `Dockerfile` provided with the challenge, we see:
  
`FROM ubuntu:22.04`
  
This line means that in building the image of this container, Docker would take the latest ubuntu version 22.04 as the base image. This tells us exactly which `libc` is used by the server.  
We can use the ROPgadget tool to find `call rsi` gadgets in our version of `libc`:
```  
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --opcode ffd6
Opcodes information
============================================================
0x000000000002b8ba : ffd6
0x000000000002bde0 : ffd6
0x00000000000301cd : ffd6
0x00000000000436d7 : ffd6
0x0000000000120e0f : ffd6
0x00000000001256aa : ffd6
0x000000000015518c : ffd6  
```
  
and `jmp rsi` gadgets:
```
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --opcode ffe6
Opcodes information
============================================================
0x000000000003d3cf : ffe6
0x00000000000519c9 : ffe6
0x0000000000075343 : ffe6
0x000000000007547c : ffe6
0x000000000007562b : ffe6
0x0000000000075a4b : ffe6
0x0000000000075a9e : ffe6
0x0000000000075dcf : ffe6
0x0000000000075e28 : ffe6
0x0000000000075e81 : ffe6
0x0000000000075f96 : ffe6
0x00000000000761a0 : ffe6
0x00000000000761d5 : ffe6
0x0000000000076226 : ffe6
...
...
```  

The `main` returns to address *7ffff7d86d90*, which is 0x1d90 from the beginning of `libc` in memory (which starts at *7ffff7d85000* in our gdb session). When ASLR is on, only the lowest 3 nibbles (*d90*) remain constant, while (in Debian based machines) 28 bits are randomized.
Since we could not find gadgets in good proximity to the original return address (closest was at zero based address 0x2b8ba), we decided to drop this option and try the third one.  
  
  
*(c) Find another address in stack we can use - or **Live Off the Land*** 
Next, we looked into the stack, from the original return address and downwards (i.e. addresses increasing), to see if we can find *interesting* addresses pointing to the stack that we can use. On our gdb session, stack addresses begin with *7fffff...*:  
  
![Stack Dump](https://github.com/nimrods8/KITCTF-CTF-2022/blob/main/stack1.png)

  
  
