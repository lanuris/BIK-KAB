#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;


struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */

#define INPUT_BUFFER_SIZE 1024
#define OUTPUT_BUFFER_SIZE (INPUT_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH)
#define HEADER_SIZE 18

class ImageController{

	private:

		EVP_CIPHER_CTX * m_ctx;
    	const EVP_CIPHER * m_cipher;

		//ecb - key, cbc - key + vector
    	crypto_config & m_cfg;

		ifstream m_inputS;
		ofstream m_outputS;

	public:

		ImageController(crypto_config & m_cfg, const std::string & in_filename, const std::string & out_filename): 
		m_ctx(nullptr), m_cipher(nullptr), m_cfg(m_cfg), m_inputS(ifstream (in_filename)), m_outputS(ofstream (out_filename)){}

		~ImageController(){
			if (m_ctx != nullptr){
				EVP_CIPHER_CTX_free(m_ctx);
			}
		}

		bool checkAndApplyCipher(bool encryption){

			// OpenSSL_add_all_ciphers();
			
			if ( !(m_cipher = EVP_get_cipherbyname(m_cfg.m_crypto_function)))
        		return false;
			
			size_t cipherKeyLen = EVP_CIPHER_key_length (m_cipher);
    		size_t cipherIVLen = EVP_CIPHER_iv_length (m_cipher);
			
			//||
			if ( m_cfg.m_key == nullptr ||  m_cfg.m_key_len < cipherKeyLen)
			{
				if (!encryption){
					cout << "Something with the key at decription mode" << endl;
					return false;
				}
				m_cfg.m_key = make_unique<uint8_t[]> (cipherKeyLen);
				m_cfg.m_key_len = cipherKeyLen;
        		RAND_bytes ( m_cfg.m_key.get(), cipherKeyLen );
			}
			if (m_cfg.m_IV == nullptr || m_cfg.m_IV_len < cipherIVLen)
			{	
				//need it
				if (cipherIVLen != 0){

					if (!encryption){
						cout << "Something with IV at decription mode" << endl;
						return false;
					}
					m_cfg.m_IV = std::make_unique<uint8_t[]>(cipherIVLen);
					m_cfg.m_IV_len = cipherIVLen;
				}
			}	
			return true;
		}
		
		bool checkStreams(){

			return m_inputS.good() && m_outputS.good();
		}

		bool copyHeader(){
			
			char header[HEADER_SIZE];

			m_inputS.read(header, HEADER_SIZE);

			// Kontrola, zda bylo načteno správné množství bytů
			if (m_inputS.gcount()!= HEADER_SIZE)
				return false;

			m_outputS.write(header, HEADER_SIZE);
			if (!m_outputS.good()){
				return false;
			}	
			return true;

		}

        bool allocContext(){

            m_ctx = EVP_CIPHER_CTX_new();
            if (m_ctx == nullptr){
                return false;
            }
			return true; 
        }

		bool init(bool encryption){
			

			if (!EVP_CipherInit_ex(m_ctx, m_cipher, nullptr, m_cfg.m_key.get(), m_cfg.m_IV.get(), int(encryption))) // context setup for our hash type
                return false;
            return true;

		}
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

};

bool crypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config, bool encryption){

	ImageController imageController (config, in_filename, out_filename);

	if (!imageController.checkStreams() || !imageController.copyHeader()){

		cout << "Something Happened with Streams!" << endl;
		return false;
	}

	if (!imageController.checkAndApplyCipher(encryption)){
		cout << "Something with cipher" << endl;
		return false;
	}

	if (!imageController.allocContext()){
		cout << "Something with alloc" << endl;
		return false;
	}

	if (!imageController.init(encryption)){
		cout << "Something with init" << endl;
		return false;
	}

	if (!imageController.update()){
		cout << "Something with update" << endl;
		return false;
	}

	if (!imageController.final()){
		cout << "Something with final" << endl;
		return false;
	}
	return true;
}

bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	return crypt_data (in_filename, out_filename, config, true);
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	return crypt_data (in_filename, out_filename, config, false);
}


#ifndef __PROGTEST__
#include <filesystem>
bool compare_files ( const char * name1, const char * name2 )
{	
	
	if (filesystem::file_size(name1) !=
		filesystem::file_size(name2) ){
			cout << "Files size different" << endl;
    		return false;
		}
	//cout << filesystem::file_size(name1) << "x" << filesystem::file_size(name2)  << endl;

	// // another option (w/o filesystem)
	// ifs1.seekg(0, std::ios::end);
    // ifs2.seekg(0, std::ios::end);
    // if (ifs1.tellg() != ifs2.tellg()) {
    //     cout << "Files size different" << endl;
    //     return false;
    // }

	ifstream ifs1 (name1);
    ifstream ifs2 (name2);
    string letters1;
    string letters2;

    while ( ifs1 >> letters1 && ifs2 >> letters2) {
        if ( letters1 != letters2 ) {
            cout << "Files not equal" << endl;
            return false;
        }
    }
	return true;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;
	
	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif /* _PROGTEST_ */
