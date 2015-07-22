# BESLibrary

### Welcome
Your data belongs to you, or more accurately your user, and sometimes, you don't want other people to see it. Encryption is the solution. This is a new encryption algorithm designed to be easy to modify, easy to implement, and easily portable. Unlike other forms of encryption, this algorithm can absorb as much entropy as you put into it. No more capped keysizes, this algorithm takes it all, and each encryption generation scheme is unique.

This library uses a secure pseudo-random number generator that has been tested against every suite available for public usage. This library provides both cryptographic primitives that you can use for your own encryption schemes, and built-in encryption schemes.


### Standard BES
The original Basyl Encryption standard uses a key generator to XOR against your file. This allows random access to your files. Since bruteforcing would require petabytes (or zettabytes and beyond depending on your password) of data to be computed each second to even crack it in a century, the strength is supposedly comparable to a One-Time Pad. An extra 40 bytes of salt is added as well, 32 bytes being a hash of the file you're encrypting, so that no two files (and even the same file) will encrypt the same way.

However, if someone were to have intercepted a plain-text copy of your file, they could replace some of the text in the file. However, this would make the hash severely different.  

Here is us using the file encryption utilities. There are different variants of this method possible.
```C#
BasylFileEncryption.Encrypt("HelloWorld.txt", "Hello");
```
There are also decrypt methods available.


Another way to encrypt is to use the BasylWriter, which can be constructed from a BasylKeyGenerator.
```C#
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
BasylWriter writer = new BasylWriter(stream, bob, true);
```
And there is a BasylReader.

You could also encrypt directly with the Basyl Key Generators.

### Cipher BES
To prevent any sort of tampering and remove any sort of derivable (indirect) XOR key, cipher bes was created. This has an internal shuffle cipher, similar in concept to the enigma machine. This is "more secure" than standard BES in the sense that it prevents a plaintext modification attack, but it prevents random access to the file. The file must be decrypted up to the point you are trying to access.

```C#
BasylCipherFileEncryption
```
