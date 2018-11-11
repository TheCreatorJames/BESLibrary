# BESLibrary

This was an encryption library I created as a Senior in High School (back in 2015). 

It taught me quite a bit about cryptography, and while components of the algorithm still hold up, I would **highly discourage** its use in production, or even for academic study. 

The encryption scheme itself implements elements of key stretching, and is designed to be "memory-hard" rather than CPU intensive. 

You might want to check out this project's [sister written in C++](https://github.com/TotalTechGeek/BESLibraryCPP), or [in Java](https://github.com/TheCreatorJames/JBESLibrary).

This library uses a custom [pseudo-random number generator](https://github.com/TotalTechGeek/BESLibrary/blob/master/PRNG.md) that has been tested against every suite available for public usage. This library provides both cryptographic primitives that you can use for your own encryption schemes, and built-in encryption schemes.


### Standard BES

This encryption scheme uses a simple XOR operation between the plaintext and CSPRNG to produce encrypted output. One of its drawbacks is that it is plaintext malleable, but this risk is mitigated by the use of a hash as an initialization vector. 

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

You could also encrypt directly with the Basyl Key Generators. As it is XOR based, decrypting is the same as encrypting.

```C#
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
byte x = 100;
bob.EncryptByte(ref x); //encrypts the byte.
```

To decrypt, using this key generator specifically, since it is XOR based, you could optionally call either EncryptByte (again) or DecryptByte, as they perform the same task. To decrypt, you must construct an exact copy of the initial key generator, which requires you to harvest the seed data (such as the hash, key1, and key2). 


```C#
BasylKeyGenerator bob = new BasylKeyGenerator("Password", /* All the options factors */, hash, key1Random, key2Random, true);
bob.DecryptByte(ref inputByte); //decrypts the byte.
```



### Cipher BES
To prevent any sort of tampering and increase error propagation (intentionally), cipher bes was created. This has an internal shuffle cipher, similar in concept to the enigma machine. This is "more secure" than standard BES in the sense that it prevents a plaintext modification attack, but it prevents random access to the file. The file must be decrypted up to the point you are trying to access.

Similar to standard BES,
```C#
BasylCipherFileEncryption.Encrypt("HelloWorld.txt", "Hello");
```

You could also encrypt using the BasylCipher directly.
```C#
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
BESCipher cipher = new BESCipher(bob);
cipher.EncryptRight(bytes);
```

To decrypt, you must reconstruct the cipher with the same key generator,
```C#
cipher.EncryptLeft(bytes);
```

### Why choose this over AES? 
You shouldn't. 

This project was created for academic purposes, and taught me quite a bit about strong pseudo-random number generation. 
