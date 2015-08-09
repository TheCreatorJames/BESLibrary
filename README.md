# BESLibrary

### Welcome
Your data belongs to you, or more accurately your user, and sometimes, you don't want other people to see it. Encryption is the solution. This is a new encryption algorithm designed to be easy to modify, easy to implement, and easily portable. Unlike other forms of encryption, this algorithm can absorb as much entropy as you put into it. No more capped keysizes, this algorithm takes it all, and each encryption generation scheme is unique. 

Also, check out this project's [sister written in C++](https://github.com/TheCreatorJames/BESLibraryCPP), or [in Java](https://github.com/TheCreatorJames/JBESLibrary).

This library uses a secure pseudo-random number generator that has been tested against every suite available for public usage. This library provides both cryptographic primitives that you can use for your own encryption schemes, and built-in encryption schemes.


### Standard BES
The original Basyl Encryption standard uses a key generator to [XOR](https://en.wikipedia.org/wiki/Exclusive_or) against your file. The encryption scheme is modeled after the [One-Time Pad](https://en.wikipedia.org/wiki/One-time_pad), also known as the  [Vernam Cipher](https://en.wikipedia.org/wiki/One-time_pad). The advantage of this version of the encryption scheme is that it allows random access to your files. Bruteforcing files using this encryption scheme requires petabytes (or zettabytes and beyond depending on the length of your password) of data to be computed each second to even crack it in a century. To ensure that two files are never encrypted the same way, a 32 byte hash of the file is used to seed the generator. An additional 8 bytes guarantee even the same hash is never encrypted twice.

This encryption scheme is slightly susceptible to a plaintext attack that allows them to replace some of the data in the file. However, because the hash of the original file is already included, this type of attack is easily prevented.

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
To prevent any sort of tampering and remove any sort of derivable (indirect) XOR key, cipher bes was created. This has an internal shuffle cipher, similar in concept to the enigma machine. This is "more secure" than standard BES in the sense that it prevents a plaintext modification attack, but it prevents random access to the file. The file must be decrypted up to the point you are trying to access.

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


### Example Tool
Try checking out this project here: 
https://github.com/TheCreatorJames/BasylEncryptionTool


