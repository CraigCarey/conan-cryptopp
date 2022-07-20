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

    std::string pt_str;
    std::string pt_file_path = "../plaintext";

    FileSource in_file(pt_file_path.data(), true, new StringSink(pt_str));

    std::cout << "plaintext: \n" << pt_str << std::endl;

    std::string cipher;

    try
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(pt_str, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    HexEncoder cout_encoder(new FileSink(std::cout));

    std::cout << "cipher text: ";
    cout_encoder.Put((const byte *)cipher.data(), cipher.size());
    cout_encoder.MessageEnd();
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

    // Write hex string to file
    HexEncoder file_encoder(new FileSink("../ciphertext.txt"));
    file_encoder.Put((const byte *)cipher.data(), cipher.size());
    file_encoder.MessageEnd();

    // Write binary string to file
    std::ofstream fs("../ciphertext.bin", std::ios::binary);
    fs.write(cipher.data(), sizeof(key));
    fs.close();
}
