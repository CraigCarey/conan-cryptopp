#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>

#include <iostream>
#include <string>

using namespace CryptoPP;

int main(int argc, char *argv[])
{
    std::string key_str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49";
    SecByteBlock key(reinterpret_cast<const byte *>(key_str.data()), key_str.size());

    std::string iv_str = "YxkXkC9FBHehRANCAAQPldOnhO2/oXjdJ";
    SecByteBlock iv(reinterpret_cast<const byte *>(iv_str.data()), iv_str.size());

    std::string ct_str_enc;
    std::string ct_file_path = "../ciphertext.txt";

    FileSource in_file(ct_file_path.data(), true, new StringSink(ct_str_enc));

    std::cout << "hex ciphertext: \n" << ct_str_enc << std::endl;

    std::string ct_str_dec;
    StringSource ss(ct_str_enc, true, new HexDecoder(new StringSink(ct_str_dec)));

    std::cout << "binary ciphertext: \n" << ct_str_dec << std::endl;

    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        std::string recovered;

        StringSource s(ct_str_dec, true,
                       new StreamTransformationFilter(d, new StringSink(recovered)));

        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
