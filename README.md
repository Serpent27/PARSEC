# PARSEC Encryption
#### Created by Alex Anderson < parsec29@protonmail.com >

PARSEC is an encryption algorithm I made because I was bored. The algorithm is based on an SP-Network and uses, by default, a 768-bit key, 512-bit block, and 32 rounds. Unlike (some) implementations of AES, the key expansion uses only constant-time operations, to prevent certain forms of attacks.

This algorithm was originally intended to run on a TI-84+CE calculator, but the calculator build broke from one of the optimizations I made to reduce the risk of timing attacks.

Design:

- The S-box and P-box are generated randomly by a script I wrote, using /dev/urandom to decide the boxes.
    - I did this to limit the possibility of the boxes preserving patterns. Also, because I'm lazy (mostly the latter).
	- If you choose any input for either box, you're guaranteed to go through every possible state before returning to your original input. This maximizes security and prevents any bits from going un-confused or un-diffused.
- The key expansion uses weird operations to strengthen the key. Each key byte gets passed through the S-box multiple times and XOR'd with the round and byte index. Also, the key expansion uses shuffling because why not?
- 32 rounds because if it's good enough for Serpent, it's good enough for me.
- 768-bit key because I decided to go ridiculously overboard. In theory, the fastest computer our universe allows to exist can only run at `~10^50` operations/sec. I decided to cut that in half ,because nobody said it couldn't be quantum, right? *right?*, and calculate how large the key would need to be to still be secure.
    - Hint: `10^50` operations/sec means `2^166` operations/sec, which cracks more 128-bit keys than I'll probably generate in my lifetime.
    - I settled on 384 bits of security, post-quantum, which means `2^218` seconds to crack the key. That should prevent the security margin from being closed by a quantum supercomputer orbiting a black hole...
- 512-bit block size, for the same reason as the key size. This is based on a block-cipher attack where an attacker can break the algorithm for every possible key, with `2^(block size)` bits ciphertext.
    - I feel comfortable making this smaller than the key, due to a trick I used, where it mixes the key with the P-box, effectively creating `2^256` possible P-boxes. That way, for the purposes of the aforementioned attack, it *should* require `2^768` bits instead of only `2^512`.

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

## Potantial changes:

Really just one thing:

- Increase the number of rounds. 32 rounds provides full diffusion 3 times, but I'm still not convinced. I'd like to see this algorithm run with 96 rounds (although I could be persuaded to reduce the number). I really only set it to 32 because anything more gets hella slow and runs my calculator out of RAM. Besides, I'd like this algorithm to be actually practical enough to *pretend* it's a real encryption algorithm, if I possibly can.

## Can I generate my own boxes?
***Yes!***

I bundled the script with this repo. Simply run `python3 ./parsec-spgen [box size] +q +inv`. You'll get 2 lists which can be imported directly into your code, in the syntax appropriate for the language you use. The first one is the box itself, and the second is the inverse box.

An S-box should be generated with the size 256, using the command `python3 ./parsec-spgen 256 +q +inv`. It's important to note the size is in bytes, not bits. As such, a 128-bit block cipher would use the box generated from `python3 ./parsec-spgen 16 +q +inv` because `16 bytes = 128 bits`.


