//
// Created by 王若璇 on 17/5/15.
//

#ifndef DES_FILEDES_HPP
#define DES_FILEDES_HPP

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <bitset>

#include "DES.hpp"

//#define DEBUG_SHOW_FILE

/**
 * @brief 对整个文件加密类,每一个加密对象一个FileDES instance
 *
 * */
class FileDES{

private:
    ifstream in;

    ///加密输出和解密输出
    ofstream encryptOut;
    ofstream decryptOut;

    ///字符串类型的密钥
    string key;

    ///实际使用的64bit类型密钥
    bitset<64> bitKey;

    ///文件末尾补充的0的个数
    int zeroNum;

    int encryptStep;

    int decryptStep;
public:
    void openFile(string filepath);

    ///@param 默认mode = 0 加密文件,设置mode = 1 则为解密
    void setOutput(string filepath,bool mode = 0);
    void setKey(int inKey);
    void setInput(string filepath);
    bool encryptFile();
    bool decryptFile();
    bool decryptFileOther();
    bool encryptFileOther();

private:

    bitset<64> stringToBitset(string str);

//    /@param in[] 默认16位
    bitset<64> charsToBitset(char in[],int len = 8);

    char* bitsetToChars(const bitset<64>& in,char* re);




};

void FileDES::openFile(string filepath) {

    ///以读的方式打开文件
    in.open(filepath,ios_base::in|ios_base::binary);
    if(!in.is_open()){
        cerr<<"open file error!"<<endl;
    }
#ifdef DEBUG_SHOW_FILE
    char buffer[16];
    while (!in.eof()){
//        in.getline(buffer,16);
        in.read(buffer,16);
        cout<<buffer;
    }

#endif


}

bool FileDES::encryptFileOther() {
    setOutput("../data/output.txt");
    setKey(123);
    while (!in.eof()){
        char inbuf[9];
        in.read(inbuf, sizeof(uint64_t));
        memset(inbuf,0, 8);
//        cout<<inbuf<<" ,,,,"<<endl;
        bitset<64> bitin = charsToBitset(inbuf,8);
        bitset<64> cipher = DES::encrypt(bitin,bitKey);
        char outbuf[8];
        char *res = bitsetToChars(cipher,outbuf);
        ///encryptOut<<outbuf;
        encryptOut.write(outbuf,8);

        bitin = charsToBitset(res,8);
        bitset<64> decrpty = DES::decrypt(bitin,bitKey);

        bitsetToChars(decrpty,outbuf);

//        cout<<outbuf<<" ...."<<endl;

    }
    in.close();
    encryptOut.close();
    return true;
}

bool FileDES::decryptFile() {
    setOutput("../data/result.txt",true);
    setInput("../data/output.txt");
    setKey(123);
    int step = 0;
    while (!in.eof()){

        uint64_t block;
        block = 0;
        in.read(reinterpret_cast<char*>(&block), sizeof(uint64_t));
        if(in.eof()){
            ///最后一次读是非法的 @todo Why
            break;
        }
        bitset<64> bitin(block);
        bitset<64> tmpres = DES::decrypt(bitset<64>(block),bitKey);
        uint64_t tmpout = tmpres.to_ullong();
        char *tmpoutbuf = reinterpret_cast<char*>(&tmpout);
        char outbuf[9];

        memset(outbuf,0, sizeof(outbuf));

        for (int i = 0; i < 8; ++i) {
            outbuf[i] = tmpoutbuf[i];
        }
//        cout<<outbuf;
        if(step!=encryptStep-1){
            decryptOut.write(outbuf,8);
            step++;
        } else{

            step++;
            ///当是最后一次解密文件时，控制读入字符串的数量
//            cout<<"ok"<<endl;
//            cout<<outbuf<<" outbuf"<<endl;
            outbuf[8-zeroNum] = '\0';
            decryptOut.write(outbuf,8-zeroNum);
        }





    }
    decryptStep = step;
    in.close();
    decryptOut.close();

    ///解密成功的标志为，加密次数和解密次数为相同值
    return decryptStep==encryptStep;
}

bitset<64> FileDES::stringToBitset(string str) {
    return bitset<64>(str);
}

void FileDES::setOutput(string filepath,bool mode) {
    if(mode){
        decryptOut.open(filepath,ios_base::out|ios_base::binary);

    } else{
        encryptOut.open(filepath,ios_base::out|ios_base::binary);
    }

}

void FileDES::setKey(int inKey) {
    bitKey = bitset<64>((unsigned long long int) inKey);
}

bitset<64> FileDES::charsToBitset(char *in,int len) {
    bitset<64> res;
    for(int i = 0;i<64;i++){
        ///将8个char的数组 转换成unsigned char* 类型，再获取每一个字符，并由按位与获得每个位上的信息
        res[i] = 0 != (*((unsigned char *)(in) + i / 8) & (1 << (7 - i % 8)));
    }
    return res;
}

char* FileDES::bitsetToChars(const bitset<64> &block,char* re){

    ///将8个字节置为0
    memset(re,0,8);
    for(int i = 0;i<64;i++){
        if(block[i]){
            *((unsigned char*)(re)+i/8) |= (1<<(7-i%8));
        }
    }
    return re;
}

void FileDES::setInput(string filepath) {
    in.open(filepath,ios_base::in|ios_base::binary);

}

bool FileDES::decryptFileOther() {
    setOutput("../data/result.txt",true);
    setInput("../data/output.txt");
    setKey(123);
    while (!in.eof()){
        char inbuf[9];
        in.read(inbuf, sizeof(uint64_t));
        bitset<64> bitin = charsToBitset(inbuf,8);
        bitset<64> tmpres = DES::decrypt(bitin,bitKey);

        char outbuf[8];

        char* res = bitsetToChars(tmpres,outbuf);
        decryptOut.write(outbuf,8);
//        cout<<outbuf;

    }
    return true;
}

bool FileDES::encryptFile() {
    encryptStep = 0;
    setOutput("../data/output.txt");
    setKey(123);
    while (!in.eof()){
        uint64_t block;
        block = 0;
        in.read(reinterpret_cast<char*>(&block), sizeof(uint64_t));
        char* tmp = reinterpret_cast<char*>(&block);
//        cout<<tmp;
        if(tmp[7]==0&&in.eof()){
            ///获得末尾补零的个数
            int pos = 7;
            while (tmp[pos]==0&&pos>=0){
                pos--;
            }
            zeroNum = 8-pos-1;
        }

        bitset<64> bitin(block);
        bitset<64> tmpres = DES::encrypt(bitset<64>(block),bitKey);
        uint64_t tmpout = tmpres.to_ullong();

        ///reinterpret_cast 有危险
        char *tmpoutbuf = reinterpret_cast<char*>(&tmpout);
        char outbuf[9];

        for (int i = 0; i < 8; ++i) {
            outbuf[i] = tmpoutbuf[i];
        }

        encryptOut.write(outbuf,8);
        encryptStep++;


//        cout<<outbuf;

    }
    in.close();
    encryptOut.close();
    return true;
}

#endif //DES_FILEDES_HPP
