# Explanation:

    gcd Function: This function calculates the greatest common divisor of two numbers using the Euclidean algorithm.
    mod_inverse Function: This function calculates the modular multiplicative inverse using the Extended Euclidean Algorithm.
    main Function:
        Initializes prime numbers p and q.
        Calculates n as the product of p and q.
        Calculates phi as (p-1) * (q-1).
        Finds an integer e such that gcd(e, phi) == 1.
        Calculates d, the modular multiplicative inverse of e modulo phi.
        Encrypts a message msg using the public key (e, n).
        Decrypts the message using the private key (d, n).

## How to run:
    g++ rsa.cpp rsa.cpp -o cma 
### To enable C++11, use the following command:
    g++ -std=c++11 rsa.cpp -o rsa.cpp -o rsa 
    g++ -std=c++11 signing.cpp -o signing.cpp -o signing 
    g++ -std=c++11 signing_no_openssl.cpp -o signing_no_openssl.cpp -o signing_no_openssl 
    
#### To run the program, use this command:
    ./rsa
    ./signing
    ./signing_no_openssl

## Theory by Vincent Bevia

Generating Public Key

1. Select two prime no's. Suppose P = 53 and Q = 59.
Now First part of the Public key  : n = P*Q = 3127.

2. We also need a small exponent say e :
   But e Must be

    -An integer.

    -Not be a factor of n.

    -1 < e < Φ(n) [Φ(n) is discussed below],
     Let us now consider it to be equal to 3.

The public key has been made of n and e

Generating Private Key

1. We need to calculate Φ(n) :
   Such that Φ(n) = (P-1)(Q-1)
      so,  Φ(n) = 3016

2. Now calculate Private Key, d :
   d = (k*Φ(n) + 1) / e for some integer k

3. For k = 2, value of d is 2011.

The private key has been made of d
    Consider two prime numbers p and q.
    Compute n = p*q
    Compute ϕ(n) = (p – 1) * (q – 1)
    Choose e such gcd(e , ϕ(n) ) = 1
    Calculate d such e*d mod ϕ(n) = 1
    Public Key {e,n} Private Key {d,n}
    Cipher text C = Pe mod n where P = plaintext
    For Decryption D = Dd mod n where D will refund the plaintext.

# Pseudocode

function gcd(a, b):
    while b ≠ 0:
        temp := b
        b := a % b
        a := temp
    return a

function mod_inverse(e, phi):
    m0 := phi
    t := 0
    q := 0
    x0 := 0
    x1 := 1
    if phi == 1:
        return 0
    while e > 1:
        q := e / phi
        t := phi
        phi := e % phi
        e := t
        t := x0
        x0 := x1 - q * x0
        x1 := t
    if x1 < 0:
        x1 += m0
    return x1

function rsa_encrypt(msg, e, n):
    return (msg ^ e) % n

function rsa_decrypt(cipher, d, n):
    return (cipher ^ d) % n

function main():
    p := 2
    q := 7

    // Value of N
    n := p * q
    print "The value of N = " + n

    // Value of phi
    phi := (p - 1) * (q - 1)
    print "The value of phi = " + phi

    // Finding e
    e := 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e := e + 1
    print "The value of e = " + e

    // Finding d
    d := mod_inverse(e, phi)
    print "The value of d = " + d

    msg := 2
    print "The message in clear = " + msg

    // Encryption: C = (msg ^ e) % n
    cipher := rsa_encrypt(msg, e, n)
    print "Encrypted message is: " + cipher

    // Decryption: msgback = (C ^ d) % n
    msgback := rsa_decrypt(cipher, d, n)
    print "Decrypted message is: " + msgback


