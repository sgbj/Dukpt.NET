Dukpt.NET
=========

Dukpt.NET is a C# implementation of the Derived Unique Key Per Transaction (DUKPT) process that's described in Annex A of ANS X9.24-2004.

About
-----

It's no secret that Annex A is hard to understand, and the entire process isn't explained in a manner that's easy to follow or translate into code. One of the reasons it's difficult to understand is that it was written from the perspective of an electrical/computer engineer that would directly implement these instruction on the devices/swipers themselves, and as a result it mentions various registers and operations that most of us don't have much experience with. So it's not necessarily for high-level software developers looking to use the process either for new software, backwards compatibility with existing technology, or logging/testing purposes.

I wrote this implementation of DUKPT for fun as a side project for my work. We already had an existing implementation of DUKPT in the project I'm maintaining, which was no longer being used and hence could be stripped out. However, the old one was convoluted and had well over 500 lines of code with lots of dependencies. This library only has about 100 lines of code and only focuses on DUKPT encryption and decryption. 

It still amazes me how [scarcely documented](http://security.stackexchange.com/questions/13309/what-is-the-dukpt-key-derivation-function) this process is, even though it seems like a fairly standard practice. Unfortunately, the advice people usually receive it to [purchase the spec](http://webstore.ansi.org/RecordDetail.aspx?sku=ANSI+X9.24-1%3A2009) for $140.

Key Management
--------------

I'm sure you can find a more extensive overview of this process [somewhere else](http://en.wikipedia.org/wiki/Derived_unique_key_per_transaction#Overview), but here's a basic outline of the technique:

1. You're given a Base Derivation Key (BDK), which you assign to a swiper (note that the same BDK _can_ be assigned to multiple swipers).
2. You'll use the BDK along with the device's own unique Key Serial Number (KSN) to generate an Initial PIN Encryption Key (IPEK) for the device.
3. You'll assign this IPEK to a swiper, which uses it to irreversibly generate a list of future keys, which it'll use to encrypt its messages. 
4. The swiper's KSN is used along with one of its future keys to encrypt a message, and after each swipe it'll increment the value of its KSN.
4. Whenever a swiper takes a card it formats the card's information into a series of tracks, each track having a particular set of information (e.g. card number, holder's name, expiration date). 
5. The swiper usually encrypts these tracks using one of its generated future keys (called the "Session Key") along with its current KSN. It'll then increment the value of its KSN and discard the future key it used.
5. At this point you'll probably have an encrypted track along with the KSN the swiper used to encrypt it.
5. It's your responsibility to determine what BDK was used to initialize this device, and from there you'll use the BDK and KSN to rederive the IPEK, which is used to rederive the Session Key, which is finally used to decrypt the message.

There's a lot of technical information to be said about key management, but this isn't the place for that. In some cases your provider/manufacturer (e.g. MagTek) will supply you with swipers that need to be initialized with an  IPEK, and your supplier will usually have a manual that walks you through that process. If you're doing encryption/decryption through a third party who also supplies swipers, they may have already loaded the devices with that information; what's more is they may not even given you the BDK that belongs to your device in order to reduce the risk of security threats.

***
__Note:__ Key management is beyond the scope of this project and this explanation. Whatever you do with your keys, just make sure it's secure.
***

One methodology I've seen that'll allow you to associate a particular KSN to a BDK is to take the current KSN you've been given, mask it to retrieve the Initial Key Serial Number (IKSN), and look up the BDK in a table that maps IKSNs to BDKs:

Example:
```
ksn = FFFF9876543210E00008
iksn = ksn & FFFFFFFFFFFFFFE00000 // FFFF9876543210E00000
```
You'd then have a table that looks like:

| IKSN                   | BDK                                |
|:----------------------:|:----------------------------------:|
| 0xFFFF9876543210E00000 | 0123456789ABCDEFFEDCBA9876543210 |
| ...                    | ...                                |

From which you could easily grab the BDK `0123456789ABCDEFFEDCBA9876543210`.

Algorithm
---------

***
__Note:__ Assume that all numeric values are hexadecimal numbers, or the representation of a sequence of bytes as a hexadecimal number.
***

The following are the BDK, KSN, and encrypted track message (cryptogram) we've been given:
```
bdk = 0123456789ABCDEFFEDCBA9876543210
ksn = FFFF9876543210E00008
cryptogram = C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12
```

Here's an example of the unencrypted track 1 data (cryptogram above), and below that is its value in hex; this is what we'll get after successfully decrypting the cryptogram:
```
%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?
2542353435323330303535313232373138395E484F47414E2F5041554C2020202020205E30383034333231303030303030303732353030303030303F00000000
```

***
__Note:__ As you're probably already aware, this algorithm is best described using big numbers, which can't be represented as literals in some programming languages (like Java or C#). However, many languages have classes that allow you to represent big numbers in other ways (e.g., java.math.BigInteger, System.Numerics.BigInteger). It's your job to adapt this algorithm so that it can be represented in your language of choice. Two small problems I encountered were ensuring the correct endianness and signedness were being used (this algorithm requires the byte order to be big endian and that unsigned integers are used). I made a utility class called BigInt to do this for me.
***

First, let's define a few standard functions:

* [DES](http://en.wikipedia.org/wiki/Data_Encryption_Standard) and [Triple DES](http://en.wikipedia.org/wiki/Triple_DES) refer to their respective cryptographic algorithms. Most programming languages have access to some implementation of these ciphers either through OpenSSL or Bouncy Castle. These ciphers are initialized with a zeroed out IV of 8 bytes, they're zero-padded, and use Cipher-Block Chaining (CBC). Let's define the signatures for these standard functions that'll be used throughout this algorithm:
  * `DesEncrypt(key, message) -> returns cryptogram`
  * `DesDecrypt(key, cryptogram) -> returns message`
  * `TripleDesEncrypt(key, message) -> returns cryptogram`
  * `TripleDesDecrypt(key, cryptogram) -> returns message`

First we must create the IPEK given then KSN and BDK:
```
CreateIpek(ksn, bdk) {
    return TripleDesEncrypt(bdk, (ksn & KsnMask) >> 16) << 64 
         | TripleDesEncrypt(bdk ^ KeyMask, (ksn & KsnMask) >> 16)
}
```

Now we can get the IPEK:
```
ipek = CreateIpek(ksn, bdk)
     = CreateIpek(FFFF9876543210E00008, 0123456789ABCDEFFEDCBA9876543210)
     = INSERT_ACTUAL_IPEK_VALUE_HERE
```

After that we need a way to get the Session Key (this one is more complicated):
```
CreateSessionKey(ipek, ksn) {
    return DeriveKey(ipek, ksn) ^ FF00000000000000FF
}
```

The DeriveKey method finds the IKSN and generates session keys until it gets to the one that corresponds to the current KSN. We define this method as:
```
DeriveKey(ipek, ksn) {
    ksnReg = ksn & FFFFFFFFFFE00000
    curKey = ipek
    for (shiftReg = 0x100000; shiftReg > 0; shiftReg >>= 1)
        if ((shiftReg & ksn & 1FFFFF) > 0)
            curKey = GenerateKey(curKey, ksnReg |= shiftReg)
    return curKey
}
```

Where the GenerateKey method looks like:
```
GenerateKey(key, ksn) {
    return EncryptRegister(key ^ KeyMask, ksn) << 64 
         | EncryptRegister(key, ksn)
}
```
And EncryptRegister looks like:
```
EncryptRegister(key, reg) {
    return (key & FFFFFFFFFFFFFFFF) ^ DesEncrypt((key & FFFFFFFFFFFFFFFF0000000000000000) >> 64, 
                                                  key & FFFFFFFFFFFFFFFF ^ reg)
}
```

Then you can generate the Session Key given the IPEK and KSN:
```
key = CreateSessionKey(ipek, ksn)
    = CreateSessionKey(INSERT_ACTUAL_IPEK_VALUE_HERE, FFFF9876543210E00008)
    = INSERT_ACTUAL_KEY_VALUE_HERE
```

Which can be used to decrypt the cryptogram:
```
message = TripleDesDecrypt(key, cryptogram)
        = TripleDesDecrypt(INSERT_ACTUAL_KEY_VALUE_HERE, C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12)
        = 2542353435323330303535313232373138395E484F47414E2F5041554C2020202020205E30383034333231303030303030303732353030303030303F00000000
        = %B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?
```

That's it, you're done!
