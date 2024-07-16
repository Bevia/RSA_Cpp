## How to run:
    g++ ./RSA_Mutual_Authentication/sign_sender_puk.cpp -o sign_sender_puk.cpp -o sign_sender_puk 

### To enable C++11, use the following command:
    g++ -std=c++11 ./RSA_Mutual_Authentication/gkp.cpp -o gkp.cpp -o gkp   
    g++ -std=c++11 ./RSA_Mutual_Authentication/sign_sender_puk.cpp -o sign_sender_puk.cpp -o sign_sender_puk 
    g++ -std=c++11 ./RSA_Mutual_Authentication/verify_signature.cpp -o verify_signature.cpp -o verify_signature        

### openssl installation
brew install openssl
find / -name rsa.h 2>/dev/null   
brew --prefix openssl  #you get /opt/homebrew/opt/openssl@3

g++ -o gkp -std=c++11 ./RSA_Mutual_Authentication/gkp.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto
g++ -o sign_sender_puk -std=c++11 ./RSA_Mutual_Authentication/sign_sender_puk.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto
g++ -o verify_signature -std=c++11 ./RSA_Mutual_Authentication/verify_signature.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#### To run the program, use this command:
    ./gkp
    ./sign_sender_puk
    ./verify_signature