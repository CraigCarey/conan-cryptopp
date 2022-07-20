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
    SecByteBlock key(reinterpret_cast<const byte *>(&key_str[0]), key_str.size());

    // Initialisation Vector
    std::string iv_str = "YxkXkC9FBHehRANCAAQPldOnhO2/oXjdJ";
    SecByteBlock iv(reinterpret_cast<const byte *>(&iv_str[0]), iv_str.size());

    std::string plain = "CBC Mode Test.";

    std::cout << "plain text: " << plain << std::endl;

    std::string cipher;

    try
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    HexEncoder encoder(new FileSink(std::cout));

    std::cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "cipher text: ";
    encoder.Put((const byte *)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        std::string recovered;

        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));

        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return 0;
}
