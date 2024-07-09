#include <iostream>
#include <cmath>

// Function to compute the greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to compute the modular multiplicative inverse
int mod_inverse(int e, int phi) {
    int m0 = phi, t, q;
    int x0 = 0, x1 = 1;
    if (phi == 1)
        return 0;
    while (e > 1) {
        q = e / phi;
        t = phi;
        phi = e % phi, e = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
        x1 += m0;
    return x1;
}

int main() {
    int p = 2;
    int q = 7;

    // Value of N
    int n = p * q;
    std::cout << "The value of N = " << n << std::endl;

    // Value of phi
    int phi = (p - 1) * (q - 1);
    std::cout << "The value of phi = " << phi << std::endl;

    // Finding e
    int e = 2;
    while (e < phi) {
        if (gcd(e, phi) == 1)
            break;
        e++;
    }
    std::cout << "The value of e = " << e << std::endl;

    // Finding d
    int d = mod_inverse(e, phi);
    std::cout << "The value of d = " << d << std::endl;

    int msg = 2;
    std::cout << "The message in clear = " << msg << std::endl;

    // Encryption: C = (msg ^ e) % n
    int c = static_cast<int>(pow(msg, e)) % n;
    std::cout << "Encrypted message is: " << c << std::endl;

    // Decryption: msgback = (C ^ d) % n
    int msgback = static_cast<int>(pow(c, d)) % n;
    std::cout << "Decrypted message is: " << msgback << std::endl;

    return 0;
}
