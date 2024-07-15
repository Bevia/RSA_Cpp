#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <random>
#include <iomanip>

// Function to generate a random prime number
int generatePrime(int lower, int upper) {
    std::vector<int> primes;
    for (int i = lower; i <= upper; ++i) {
        bool isPrime = true;
        for (int j = 2; j <= std::sqrt(i); ++j) {
            if (i % j == 0) {
                isPrime = false;
                break;
            }
        }
        if (isPrime) {
            primes.push_back(i);
        }
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, primes.size() - 1);
    return primes[dis(gen)];
}

// Function to calculate the greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to calculate the modular inverse
int modInverse(int e, int phi) {
    int t = 0;
    int newT = 1;
    int r = phi;
    int newR = e;

    while (newR != 0) {
        int quotient = r / newR;
        int tempT = t;
        t = newT;
        newT = tempT - quotient * newT;

        int tempR = r;
        r = newR;
        newR = tempR - quotient * newR;
    }

    if (r > 1) {
        throw std::runtime_error("e is not invertible");
    }
    if (t < 0) {
        t += phi;
    }

    return t;
}

// Function to perform modular exponentiation
int modExp(int base, int exp, int mod) {
    int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

// Function to generate RSA key pair
void generateKeyPair(int& n, int& e, int& d) {
    int p = generatePrime(11, 19);
    int q = generatePrime(11, 19);
    n = p * q;
    int phi = (p - 1) * (q - 1);

    e = 3;
    while (gcd(e, phi) != 1) {
        ++e;
    }

    d = modInverse(e, phi);
}

// Function to sign a message
int signMessage(int d, int n, int message) {
    return modExp(message, d, n);
}

// Function to verify a signature
bool verifySignature(int e, int n, int message, int signature) {
    return modExp(signature, e, n) == message;
}

int main() {
    int n, e, d;
    generateKeyPair(n, e, d);

    std::cout << "Public Key: (" << n << ", " << e << ")\n";
    std::cout << "Private Key: (" << n << ", " << d << ")\n";

    int message = 42;
    std::cout << "Message: " << message << "\n";

    int signature = signMessage(d, n, message);
    std::cout << "Signature: " << signature << "\n";

    bool isValid = verifySignature(e, n, message, signature);
    if (isValid) {
        std::cout << "The signature is valid.\n";
    } else {
        std::cout << "The signature is invalid.\n";
    }

    return 0;
}
