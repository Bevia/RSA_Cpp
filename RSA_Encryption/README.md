## How to run:
    g++ signing.cpp ./RSA_Encryption/encrypting.cpp -o encrypting.cpp -o encrypting 

### To enable C++11, use the following command:
    g++ -std=c++11 ./RSA_Encryption/encrypting.cpp -o encrypting.cpp -o encrypting 

### openssl installation
brew install openssl
find / -name rsa.h 2>/dev/null   
brew --prefix openssl  #you get /opt/homebrew/opt/openssl@3

g++ -o encrypting -std=c++11 ./RSA_Encryption/encrypting.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#### To run the program, use this command:
    ./encrypting