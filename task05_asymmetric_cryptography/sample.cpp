#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

#define INPUT_BUFFER_SIZE 1024
#define OUTPUT_BUFFER_SIZE (INPUT_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH)


struct crypto_config
{   
    //veřejný - seal /private - open klíč, který bude použit k zašifrování symetrického klíče, (jen text, ktery nactem)
	string_view m_keyFile; 
    //název symetrické šifry použité pro šifrování, (jen text, ktery nactem)
	string_view m_symmetricCipher;
};


class HybridCypherController { 

    EVP_CIPHER_CTX * m_ctx;
    const EVP_CIPHER * m_cipher;


    crypto_config m_config;

    
    unsigned char m_IV[EVP_MAX_IV_LENGTH];
    // encrypted symmetric cipher key
    unsigned char * m_symEncKey; 
    int m_symEncKeyLenght;

    // public or private key (we will use it for key encryption)
    EVP_PKEY * m_key; 

    ifstream m_inputS;
	ofstream m_outputS;


    public:
        
        HybridCypherController(string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher):
            m_ctx(nullptr), m_cipher(nullptr),
            m_config({publicKeyFile, symmetricCipher}),
            m_symEncKey(nullptr), m_symEncKeyLenght(0),
            m_key(nullptr),
            m_inputS(ifstream (string(inFile))), m_outputS(ofstream (string(outFile))){}

        HybridCypherController (string_view inFile, string_view outFile, string_view privateKeyFile):
            m_ctx(nullptr), m_cipher(nullptr),
            m_config({privateKeyFile}), //m_config({privateKeyFile, ""}),
            m_symEncKey(nullptr), m_symEncKeyLenght(0),
            m_key(nullptr),
            m_inputS(ifstream (inFile.data())), m_outputS(ofstream (outFile.data())){}


        ~HybridCypherController(){
            if (m_ctx)
                EVP_CIPHER_CTX_free (m_ctx);
            
            if (m_key)
                EVP_PKEY_free (m_key);
            
            if (m_symEncKey)
                free (m_symEncKey);
        }    


        bool allocContext(){

            m_ctx = EVP_CIPHER_CTX_new();
            if (m_ctx == nullptr){
                return false;
            }
			return true; 
        }

        //seal == publicKey
        bool readKey (bool publicKey){
            
            FILE * openFile;

            if (!(openFile = fopen(m_config.m_keyFile.data(), "r"))){
                return false;
            }

            if ( publicKey )
                m_key = PEM_read_PUBKEY ( openFile, NULL, NULL, NULL  );
            else
                m_key = PEM_read_PrivateKey ( openFile, NULL, NULL, NULL );

            fclose (openFile);
            if (!m_key){
                return false;
            }
            return true;
        }

        bool checkStreams(){

			return m_inputS.good() && m_outputS.good();
		}

        bool init(bool seal){

            if (!allocContext()){
                return false;
            }

            if ( !(m_cipher = EVP_get_cipherbyname ( m_config.m_symmetricCipher.data())))
                return false;

            if (!readKey(seal)){
                return false;
            }  

            if (seal){
                m_symEncKey = ( unsigned char * ) malloc ( EVP_PKEY_size(m_key) );
                if (!EVP_SealInit (m_ctx, m_cipher, &m_symEncKey, &m_symEncKeyLenght , m_IV, &m_key, 1 ) )
                    return false;
            } 

            else
            {
                if (!EVP_OpenInit(m_ctx, m_cipher, m_symEncKey, m_symEncKeyLenght , m_IV, m_key))
                    return false;
            }
            return true; 
        }
        //EVP_OpenUpdate and EVP_SealUpdate == EVP_CipherUpdate
        bool update(){
            
            char inputBuffer[INPUT_BUFFER_SIZE];
			//vysledek muze byt vetsi
			char outputBuffer[OUTPUT_BUFFER_SIZE];

			int outputRealBufferSize;	

			while (checkStreams()){

				m_inputS.read(inputBuffer, INPUT_BUFFER_SIZE);

				if (!EVP_CipherUpdate(m_ctx,
								  reinterpret_cast<unsigned char*> (outputBuffer), &outputRealBufferSize,
								  reinterpret_cast<unsigned char*> (inputBuffer), m_inputS.gcount())) // context setup for our hash type			  
                	return false;

				m_outputS.write(outputBuffer,outputRealBufferSize);
			}
			
			if (!m_inputS.eof())
            	return false;

			return true;
        }
        //EVP_OpenFinal and EVP_SealFinal == EVP_CipherFinal
        bool final(){

			char outputBuffer[OUTPUT_BUFFER_SIZE];
			int outputRealBufferSize;
			if (!EVP_CipherFinal(m_ctx, reinterpret_cast<unsigned char*>(outputBuffer), &outputRealBufferSize))
				return false;

			m_outputS.write(outputBuffer,outputRealBufferSize);	
			if (!m_outputS.good())
				return false;
			return true;	
		}

        //0	4 B	int	NID - numerical identifier for an OpenSSL cipher. (Použitá symetrická šifra)
        //4	4 B	int	EKlen - délka zašifrovaného klíče
        //8	EKlen B	pole unsigned char	Zašifrovaný klíč pomocí RSA
        //8 + EKlen	IVlen B	pole unsigned char	Inicializační vektor (pokud je potřeba)
        //8 + EKlen + IVlen	—	pole unsigned char	Zašifrovaná data
        bool writeHeader (){

            int nid = EVP_CIPHER_nid( m_cipher ); 

            m_outputS.write ( (char*)&nid, sizeof(int) );
            m_outputS.write ( (char*)&m_symEncKeyLenght, sizeof(int) );
            m_outputS.write ( (char*)m_symEncKey, m_symEncKeyLenght);
            m_outputS.write ( (char*)m_IV, EVP_CIPHER_iv_length(m_cipher) );

            if (!m_outputS.good())
                return false;

            return true;
        }

        bool readConfiguration() 
        {   
            if (!m_inputS.good())
                return false;
    
            int nid = 0;
            m_inputS.read ((char*)&nid, 4);

            if ( m_inputS.gcount() != 4 || nid <= 0 )
                return false;

            m_symEncKeyLenght = 0;
            m_inputS.read ((char*)&m_symEncKeyLenght, 4);

            if (m_inputS.gcount() != 4 || m_symEncKeyLenght <= 0 )
                return false;

            if ( !(m_cipher = EVP_get_cipherbynid (nid)))
                return false;
            m_config.m_symmetricCipher = EVP_CIPHER_name (m_cipher);

            m_symEncKey = (unsigned char *) malloc (m_symEncKeyLenght);
            m_inputS.read (reinterpret_cast<char *>(m_symEncKey), m_symEncKeyLenght);

            if (m_inputS.gcount() != m_symEncKeyLenght)
                return false;
            int ivLenght;
            if ((ivLenght = EVP_CIPHER_iv_length (m_cipher) ) != 0 ) {
                m_inputS.read (reinterpret_cast<char *>(m_IV), ivLenght );
                if ( m_inputS.gcount() != ivLenght )
                    return false;
            }
            return true;
        }

};

bool seal( string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher )
{   
    //check input data
    if (!inFile.data() || !outFile.data() || !publicKeyFile.data() || !symmetricCipher.data()){
        cout << "Something wrong with input data" <<endl;
        return false; 
    }
        

    HybridCypherController hybridCypherController(inFile, outFile, publicKeyFile, symmetricCipher);

    if ( !hybridCypherController.init(true))  {
        cout << "Something wrong with init" <<endl;
        std::remove(outFile.data());
        return false;
    }

    if (!hybridCypherController.writeHeader()){
        cout << "Something wrong with header" <<endl;
        std::remove(outFile.data());
        return false;
    }

    if (!hybridCypherController.update()){
        cout << "Something wrong with update" <<endl;
        std::remove(outFile.data());
        return false;
    }

    if (!hybridCypherController.final()){
        cout << "Something wrong with final" <<endl;
        std::remove(outFile.data());
        return false;
    }

    return true;
}


bool open( string_view inFile, string_view outFile, string_view privateKeyFile )
{   
    //check input data
    if (!inFile.data() || !outFile.data() || !privateKeyFile.data()){
        cout << "Something wrong with input data" <<endl;
        return false; 
    }

    HybridCypherController hybridCypherController(inFile, outFile, privateKeyFile);

    if (!hybridCypherController.readConfiguration()) {
        cout << "Something wrong with read configuration" <<endl;
        std::remove(outFile.data());
        return false;    
    }

    if ( !hybridCypherController.init(false))  {
        cout << "Something wrong with init" <<endl;
        std::remove(outFile.data());
        return false;
    }

    if (!hybridCypherController.update()){
        cout << "Something wrong with update" <<endl;
        std::remove(outFile.data());
        return false;
    }

    if (!hybridCypherController.final()){
        cout << "Something wrong with final" <<endl;
        std::remove(outFile.data());
        return false;
    }

    return true;
}



#ifndef __PROGTEST__

int main ( void )
{
    assert( seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

