Dukpt.NET
=========

Dukpt.NET is a C# implementation of the Derived Unique Key Per Transaction (DUKPT) process that's described in Annex A of ANS X9.24-2004.

About
-----

It's no secret that Annex A is hard to understand and the entire process isn't explained in a manner that's easy to follow or translate into code. One of the reasons it's difficult to understand is that it was written for devices that (at the time) were limited and only had access to so many registers and operations, and not necessarily for high-level software developers looking to use the process either for new software, backwards compatibility with existing technology, or logging/testing purposes.

I wrote this implementation of DUKPT for fun as a side project for my work. We already had an existing implementation of DUKPT in the project I'm maintaining, which was no longer being used and hence could be stripped out. However, the old one was convoluted and had well over 500 lines of code with lots of dependencies. It still amazes me how [scarcely documented](http://security.stackexchange.com/questions/13309/what-is-the-dukpt-key-derivation-function) this process is, even though it seems like a fairly standard practice. Unfortunately, the advice people usually receive it to [purchase the spec](http://webstore.ansi.org/RecordDetail.aspx?sku=ANSI+X9.24-1%3A2009) for $140.

Key Management
--------------

I'm sure you can find a more extensive overview of this process [somewhere else](http://en.wikipedia.org/wiki/Derived_unique_key_per_transaction#Overview), but here's a basic outline of the technique:

1. You're given a Base Derivation Key (BDK), which you assign to a swiper (note that the same BDK _can_ be assigned to multiple swipers).
2. You'll use the BDK along with the device's own unique Key Serial Number (KSN) to generate an Initial PIN Encryption Key (IPEK) for the device.
3. You'll assign this IPEK to a swiper, which uses it to irreversibly generate a list of future keys, which it'll use to encrypt its messages. 
4. The swiper also has a Key Serial Number (KSN), which it uses along with one of its future keys to encrypt a message, and after each swiper it'll increment the value of its KSN.
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
```Java
ksn = 0xFFFF9876543210E00008
iksn = ksn & 0xFFFFFFFFFFFFFFE00000 // 0xFFFF9876543210E00000
```
You'd then have a table that looks like:

| IKSN                   | BDK                                |
|:----------------------:|:----------------------------------:|
| 0xFFFF9876543210E00000 | 0x0123456789ABCDEFFEDCBA9876543210 |
| ...                    | ...                                |

From which you could easily grab the BDK `0x0123456789ABCDEFFEDCBA9876543210`.
