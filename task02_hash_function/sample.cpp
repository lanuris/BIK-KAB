 #ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>


using namespace std;

#endif /* __PROGTEST__ */


string hashToHexString(const unsigned char *hash, unsigned int length) {

    stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}
   
class HashController {

    private:
        EVP_MD_CTX * m_ctx;  // struktura kontextu
        const EVP_MD * m_type; // typ pouzite hashovaci funkce

        unsigned char* m_hash; // char pole pro hash - 64 bytu (max pro sha 512)
        unsigned int m_hashLength;

        unsigned int m_maxHashSize;

    public:
        HashController (unsigned int maxHashSize):  m_ctx(nullptr), m_type(EVP_sha512()),  m_hash(nullptr), m_hashLength(0), m_maxHashSize(maxHashSize) {}

        HashController (unsigned int maxHashSize, const EVP_MD * hashType):  m_ctx(nullptr), m_type(hashType), m_hash(nullptr), m_hashLength(0), m_maxHashSize(maxHashSize) {}


        ~HashController (){
            if (m_ctx != nullptr)
                EVP_MD_CTX_free(m_ctx);

            if ( m_hash )
                free ( m_hash );    
        }
        //allocate memory
        int allocContextAndHash(){
            m_ctx = EVP_MD_CTX_new();
            if (m_ctx == nullptr){
                return 0;
            }
            m_hash = ( unsigned char * ) calloc ( m_maxHashSize, sizeof ( unsigned char ) );
            if ( ! m_hash ) {
                return 0;
            } 
            return 1;   
        }

        int initContext(){
            if (!EVP_DigestInit_ex(m_ctx, m_type, NULL)) // context setup for our hash type
                return 0;
            return 1;
        }

        int updateContext(unsigned char * message, size_t messageSize){
            if (!EVP_DigestUpdate(m_ctx, message, messageSize)) // feed the message in
                return 0;
            return 1;    
        }

        int finalContext (){
            if (!EVP_DigestFinal_ex(m_ctx, m_hash, &m_hashLength)) // get the hash
                return 0;
            return 1;    
        }

        bool checkHash(int numberZeroBits){

            bool hasRequiredZeros = true;
            for (int i = 0; i < numberZeroBits / 8; ++i) {
                if (m_hash[i] != 0) {
                    hasRequiredZeros = false;
                    break;
                }
            } 
            if (hasRequiredZeros && (m_hash[numberZeroBits / 8] >> (8 - (numberZeroBits % 8))) == 0)
                return true; // Pokud požadovaný počet nulových bitů je nalezen, ukončíme cyklus

            return false;
        }
        
        unsigned char* getHash(){
            return m_hash;
        }

        unsigned int getLength(){
            return m_hashLength;
        }
    
};

int findHashEx (int numberZeroBits, string & outputMessage, string & outputHash, string_view hashType) {
    
    const EVP_MD * hashFuncType = EVP_get_digestbyname(hashType.data());
    auto mdSize = EVP_MD_size(hashFuncType);
     //|| numberZeroBits % 8 != 0
    //zakladni podminka
    if (numberZeroBits < 0 || numberZeroBits > mdSize || hashType.empty()) return 0;

    HashController hashController(mdSize, hashFuncType);


    // Buffer pro vygenerovanou zprávu
    unsigned char message [EVP_MAX_MD_SIZE];
    
    if (!hashController.allocContextAndHash()){
        return 0;
    }
    


    while (true){

        //nahodny retezec
        RAND_bytes (reinterpret_cast<unsigned char*>(message), mdSize );

        if (!hashController.initContext() || !hashController.updateContext(message, mdSize) || !hashController.finalContext())
            return 0;

        if (hashController.checkHash(numberZeroBits)){
            break;
        }       
    }
    
    outputMessage = hashToHexString(message, mdSize);

    outputHash = hashToHexString(hashController.getHash(), mdSize);
    return 1;
}

int findHash (int numberZeroBits, string & outputMessage, string & outputHash) {

    return findHashEx (numberZeroBits,outputMessage, outputHash, "sha512");
}

#ifndef __PROGTEST__


unsigned char charToHex ( unsigned char c ) {
    if ( c > 'F' || ( c < 'A' && c >'9' ) || c < '0' )
        return 0;
    if ( c >= 'A' )
        return c - 55;
    return c - '0';
}

int checkHash(int bits, const string & hash) {
    
   int zeroBitCounter = 0;
    const int totalBits = 128;

    for (size_t i = 0; i < totalBits; ++i) {
        unsigned char hexValue = charToHex(hash[i]);

        for (int j = 0; j < 4; ++j) {
            // Check if the current bit is set
            if ((hexValue & 0b00001000) != 0)
                return (zeroBitCounter >= bits);

            // Move to the next bit
            ++zeroBitCounter;
            hexValue <<= 1;
        }
    }
    return zeroBitCounter >= bits;
}

int main (void) {
    string hash, message;
    //findHash(0, message, hash);
    assert(findHash(0, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(0, hash));
    message.clear();
    hash.clear();
    assert(findHash(1, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(1, hash));
    message.clear();
    hash.clear();
    assert(findHash(2, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(2, hash));
    message.clear();
    hash.clear();
    assert(findHash(3, message, hash) == 1);
    assert(!message.empty() && !hash.empty() && checkHash(3, hash));
    message.clear();
    hash.clear();
    assert(findHash(-1, message, hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */

