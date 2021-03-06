# PARSEC Encryption
#### Created by Alex Anderson < parsec29@protonmail.com >

#### *Important:*
This implementation of PARSEC should not be used on systems that try to cache memory accesses, due to cache timing vulnerabilities. I started working on an x86_64 implementation handling data exclusively on the CPU registers, thereby bypassing caching issues; but I'm not sure I'll actually get around to writing that. Until then you should stick to a good implementation of AES.

Besides, this is basically a reference implementation for an algorithm I personally wouldn't trust until it gets properly reviewed (assuming that ever happens), so yeah...

## License
PARSEC is licensed under the **MIT** license.
I originally published this software under the GPLv3 license, but have since relicensed it to allow use in closed-source projects (although I personally despise closed-source).

The TI-84+CE build of this software is compiled by CEDev which can be found at https://github.com/CE-Programming/toolchain/
CEDev is a separate work and is not created by me.

## Key size

*In a (slightly embarrassing) realization I remembered I have been using a 1024-bit key, instead of 768 bits, due to an optimization where I replace `n % key_size` with `n & key_size_bitmask`. I made this optimization to mitigate potential timing attacks related to the non-constant timing of the C modulus operator, but then forgot the key size now must be a power of 2.*

*Since the difference doesn't harm security, you can just pretend it's a 768-bit key, then add 256 more bits!*

PARSEC is an encryption algorithm I made because I was bored. The algorithm is based on an SP-Network and uses, by default, a 1024-bit key, 512-bit block, and 32 rounds. The algorithm uses only constant-time operations, because those are the least susceptable to side-channel attacks.

This algorithm was originally intended to run on a TI-84+CE calculator, but the calculator build broke from one of the optimizations I made to reduce the risk of timing attacks.

***Update:*** It turns out the issue was the `0bX` notation of binary data. As such, I converted instances from binary to hex notation. Apparently the TI-84+CE compiler doesn't support certain notations for integer data (which doesn't surprise me).

For users intending on cross-compatibility between the TI-84+CE and other systems, it should be noted that the Linux build adds a newline to the input, whether you like it or not. Since the TI-84+CE doesn't do the same, your key will always be different between the 2 platforms, preventing cross-compatibility. It should be simple enough to fix this, but I don't feel like fixing it, so you'll have to do it yourself if you really want to.

The TI-84+CE version only uses 128-bit blocks and 256-bit keys. Why? Because it's a calculator and runs out of memory with my ridiculously overkill block and key sizes. You can go larger with the sizes before it breaks on the calculator, but we're not gonna be hiding messages from the Galactic Federation on our TI-84s, now are we?

**Design:**

- The S-box and P-box are generated randomly by a script I wrote, using /dev/urandom to decide the boxes.
    - I did this to limit the possibility of the boxes preserving patterns. Also, because I'm lazy (mostly the latter).
	- If you choose any input for either box, you're guaranteed to go through every possible state before returning to your original input. This maximizes security and prevents any bits from going un-confused or un-diffused.
- The key expansion uses weird operations to strengthen the key. Each key byte gets passed through the S-box multiple times and XOR'd with the round and byte index. Also, the key expansion uses shuffling because why not?
- 32 rounds because if it's good enough for Serpent, it's good enough for me.
- 1024-bit key because I decided to go ridiculously overboard. In theory, the fastest computer our universe allows to exist can only run at `~10^50` operations/sec. I decided to cut that in half ,because nobody said it couldn't be quantum, right? *right?*, and calculate how large the key would need to be to still be secure.
    - Hint: `10^50` operations/sec means `2^166` operations/sec, which cracks more 128-bit keys than I'll probably generate in my lifetime.
    - I settled on 384 bits of security, post-quantum, which means `2^218` seconds to crack the key for the previously mentioned, theoretical *fastest computer in the universe*. That should prevent the security margin from being closed by a quantum supercomputer orbiting a black hole... But, since the key size is a power of 2, I used a 1024-bit key, which becomes 512 bits of security, and thus increasing the security margin even more; as if anyone cares at that point.
	- For anyone who actually cares, the 1024-bit key means a key bruteforce will take `2^346` seconds for an attacker with such an "ideal computer". However, the challenge of bruteforcing the key becomes unimportant when you consider the block size:
- 512-bit block size, for the same reason as the key size. This is based on a block-cipher attack where an attacker can break the algorithm for every possible key, with `2^(block size)` blocks ciphertext.
    - I feel comfortable making this smaller than the key, since from  research I;ve seen, it's expected that the universe isn't capable of storing anywhere close to this much data.

## Why did I make this algorithm so ridiculous?
#### Because I felt like it, of course!
I told you I made this because I was bored... Please, no stupid questions.

I made this algorithm with a few fundamental assumptions:

1. The attacker is part of a level 4 civilization and has *literally* all the resources in the universe to break my encryption.
2. The attacker can't just *know* what I said because that would be too simple.
3. SP-networks can be made secure against every form of attack, even those we don't know about, by simply adding more bits and weirder boxes.
4. I know what I'm doing... ***I don't but let's pretend, okay?***

## Actual security
If you change the parameters to use a 128-bit block size and 256-bit key (the appropriate P-box is in the code, but commented out) you should get a pretty rational substitute for AES-256, or even Serpent, for that matter. SP-networks are a pretty simple thing, and a secure S-box and P-box means your algorithm should perform as well as any other, for the same number of rounds and key size. Key expansion isn't of too much concern - AES has been noted for its less-than-ideal key expansion, which has been overlooked because it's not actually that important... As long as it's not a totally useless key cycle you probably haven't messed up too bad.

That said, I don't do *not too bad* so I made my key cycle random, dumb, and more time consuming than it needs to be. All in the name of security!

## Potential changes:

Really just two things:

- Increase the number of rounds. 32 rounds provides full diffusion 3 times, but I'm still not convinced. I'd like to see this algorithm run with 96 rounds (although I could be persuaded to reduce the number). I really only set it to 32 because anything more gets hella slow and runs my calculator out of RAM. Besides, I'd like this algorithm to be actually practical enough to *pretend* it's a real encryption algorithm, if I possibly can.

## Can I generate my own boxes?
***Yes!***

I bundled the script with this repo. Simply run `python3 ./psec-spgen [box size] +q +inv`. You'll get 2 lists which can be imported directly into your code, in the syntax appropriate for the language you use. The first one is the box itself, and the second is the inverse box.

An S-box should be generated with the size 256, using the command `python3 ./psec-spgen 256 +q +inv`. It's important to note the size is in bytes, not bits. As such, a 128-bit block cipher would use the box generated from `python3 ./psec-spgen 16 +q +inv` because `16 bytes = 128 bits`.


## Building and running:
To build, simply run `gcc src/main.c -o [output]`. If you want to use compiler optimizations, run `gcc src/main.c -o [output] -O3`.
I have already built the file `./lxtest` which should run fine on most Linux systems.

## Encryption modes of operation:
I decided to create a pseudo-authenticated mode of operation, optimized for full-disk encryption:
***PCM (PARSEC Counter Mode)***

A mode of operation I'm creating specifically for full-disk encryption.
The purpose of this mode is to provide a paralleizable, tamper-resistant mode of operation without regenerating the key cycle for each block; since key cycle generation slows throughput.

How do I achieve this? By encrypting the message through 1 substitution round, XORing the block index, then performing the actual encryption.
This way I don't need to worry about certain(chosen?) plaintexts generating predictable ciphertext - the key is factored into the transformation, and the S-box removes bitwise patterns that can lead to predictable output.

With this mode of operation, any change in the message should lead to random ciphertext.
It should be noted that this isn't an authenticated encryption mode. It simply ensures that any changes made to the ciphertext become meaningless upon decryption, preventing any intelligent form of data manipulation. Some filesystems, such as BTRFS, store a hash of their file objects (ex. CRC32), which should provide sufficient authentication considering an attacker needs to physically access the machine for each attempt, in such an attack. The hash also doesn't need to be a secure hash, since the encryption itself is meant to provide the security for the hashing algorithm. The hash needs only to detect random changes, which CRC32 does well.

You could make a filesystem that keeps and verifies the SHA-256 of each file, if you really wanted to, and thus increase the security to 128 bits but the attacker needs to physically tamper with the data on-disk for each attempt, and wait for the user to decrypt it, which makes 32 bits of security enough. Also, the hash may be the same but the data on-disk will still be random and meaningless, defeating the entire point of such an attack. The attacker can't predict or control what the data will be, making the attack fairly pointless to try in the first place.
