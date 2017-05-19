#include <iostream>
#include "../src/DES.hpp"
#include "../src/fileDES.hpp"

#include <bitset>
#include <cstdio>

using namespace std;

//#define DEBUG_SHOW


void testBitset() {
    bitset<4> a(15);
    bitset<4> b(4);

    cout << a << " " << b << endl;

    swap(a, b);

    cout << a << " " << b << endl;
}

void show(bitset<64> in) {
    bitset<32> a, b;

    for (int i = 0; i < 32; i++) {
        b[i] = in[i];
    }
    for (int i = 0; i < 32; i++) {
        a[i] = in[32 + i];
    }

    printf("%X%X\n", (unsigned int) a.to_ulong(), (unsigned int) b.to_ulong());
}

void testEncrypt() {

    bitset<64> in(0x1234567890abcdef);

//    cout<<in.size()<<endl;
//    printf("%X\n", in.to_ulong());

    bitset<64> key(0x111111111111111);

    auto res = DES::encrypt(in, key);

    cout<<DES::toString(res)<<endl;

    auto pre = DES::decrypt(res, key);

    cout<<DES::toString(pre)<<endl;

//    cout<<pre.size()<<endl;

//    show(key);

#ifdef DEBUG_SHOW
    show(in);

    show(res);

    show(pre);

    cout<<DES::toString(in)<<endl;
    cout<<DES::toString(res)<<endl;
    cout<<DES::toString(pre)<<endl;
//    printf("%X\n", res.to_ulong());

#endif
}

void testFileDES() {
    FileDES fileDES;
    fileDES.openFile("../data/input.txt");
    fileDES.encryptFile();
    fileDES.decryptFile();
}

void testIfstream() {
    ifstream in;
    in.open("../data/input1.txt");
    while (!in.eof()) {
        uint64_t block;


        ///@bug 最后只读入了一个字符时，后面的字符并没有变化,解决bug方案为使，block = 0
        block = 0;
        in.read(reinterpret_cast<char *>(&block), sizeof(block));

        char *out = reinterpret_cast<char *>(&block);

        char outbuf[9];
        memset(outbuf, 0, sizeof(outbuf));
        strcpy(outbuf, out);
        outbuf[8] = '\0';
        cout << outbuf;
    }
}

void useFileDES(){

//    FileDES des;
//    des.setInput("../data/input.txt"); ///your input file path
//    des.setOutput("../data/encrypt.txt",0); ///your encrypt output file path
//    des.setKey("123456"); ///your key
//    des.encryptFile(); ///encrypt file
//    des.setOutput("../data/decrypt.txt",1); ///your decrypt output file path
//    des.decryptFile(); ///decrypt file
};

int main() {
//    cout<< sizeof(uint64_t)<<endl;

//    testFileDES();
    testEncrypt();

//    testIfstream();
//    Ui_MainWindow ab;




    return 0;
}