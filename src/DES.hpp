//
// Created by 王若璇 on 17/5/10.
//

#ifndef DES_DES_HPP
#define DES_DES_HPP

#include <bitset>
#include <iostream>

using namespace std;

/**
 * @brief DES加密算法类，DES基于对称加密的算法
 * @public interface
 *            encrypt: 加密，输入64位明文，密钥，返回64位密文
 *                  @param in,key (bitset<64>) 64
 *                  @return ciphertext (bitset<64>)
 *
 *            decrypt: 解密，输入64位密文，密钥，返回64位明文
 *                  @param in,key (bitset<64>) 64
 *                  @return ciphertext (bitset<64>)
 *
 *            toString: 返回bitset<64> 的16进制字符串形式
 *                  @param in (bitset<64>) 64
 *                  @return string
 *
 *
 * */

class DES {
public:
    enum SIZE {
        BLOCK = 64,
        KEY = 56,
        CODE = 48,

        HALF_BLOCK = 32,
        HALF_KEY = 28,
    };

private:
    const static int ipTable[64];
    const static int eTable[48];
    const static int pTable[32];
    const static int sTable[8][64];
    const static int ppTable[64];
    const static int leftShift[16];
    const static int pc1Table[56];
    const static int pc2Table[48];
    const static char bitTable[16];

public:


    static bitset<SIZE::BLOCK> encrypt(const bitset<SIZE::BLOCK> &in, const bitset<SIZE::BLOCK> &key);

    static bitset<SIZE::BLOCK> decrypt(const bitset<SIZE::BLOCK> &in, const bitset<SIZE::BLOCK> &key);


    ///设置64位
    static string toString(const bitset<SIZE::BLOCK> block);

private:
    static char bit4ToChar(const bitset<4> bit4);

    ///@brief 将输入的input经过IP变换分为左右两个部分
    static void ip(const bitset<SIZE::BLOCK> &input, bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r);

    ///@brief l' = r, r = l^f(r,k)
    static void turnLR(bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r, const bitset<SIZE::CODE> &key);

    static bitset<SIZE::HALF_BLOCK> f(bitset<SIZE::HALF_BLOCK> &in, const bitset<SIZE::CODE> &key);

    ///@brief 密钥置换
    static void keyTurn(const bitset<SIZE::BLOCK> &key, bitset<SIZE::HALF_KEY> &l, bitset<SIZE::HALF_KEY> &r);

    ///@brief 循环左移操作

    static void leftMove(bitset<SIZE::HALF_KEY> &l, bitset<SIZE::HALF_KEY> &r, int step);

    static void
    compressKey(const bitset<SIZE::HALF_KEY> &l, const bitset<SIZE::HALF_KEY> &r, bitset<SIZE::CODE> resKey);

    static void finalIp(bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r, bitset<SIZE::BLOCK> &res);

    static bitset<SIZE::CODE> getKey(int step, const bitset<SIZE::BLOCK> key);

};

const int DES::ipTable[64] = {
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

const int DES::eTable[48] = {
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};
const int DES::pTable[32] = {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

const int DES::ppTable[64] = {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

const int DES::leftShift[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

const int DES::pc1Table[56] = {
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
};
const int DES::pc2Table[48] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

const char DES::bitTable[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};
const int DES::sTable[8][64] = {
        {//S1
                14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
                0,  15, 7,  4,  14, 2,  13, 1,  10, 6, 12, 11, 9,  5,  3,  8,
                4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
                15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0, 6,  13
        },
        {//S2
                15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
                3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9,  11, 5,
                0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
                13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5, 14, 9
        },
        {//S3
                10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
                13, 7,  0,  9,  3,  4,  6,  10, 2,  8, 5,  14, 12, 11, 15, 1,
                13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
                1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5, 2,  12
        },
        {//S4
                7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
                13, 8,  11, 5,  6,  15, 0,  3,  4,  7, 2,  12, 1,  10, 14, 9,
                10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
                3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14
        },
        {//S5
                2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
                14, 11, 2,  12, 4,  7,  13, 1,  5,  0, 15, 10, 3,  9,  8,  6,
                4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
                11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3
        },
        {//S6
                12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
                10, 15, 4,  2,  7,  12, 9,  5,  6,  1, 13, 14, 0,  11, 3,  8,
                9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
                4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0, 8,  13
        },
        {//S7
                4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
                13, 0,  11, 7,  4,  9,  1,  10, 14, 3, 5,  12, 2,  15, 8,  6,
                1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
                6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2, 3,  12
        },
        {//S8
                13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
                1,  15, 13, 8,  10, 3,  7,  4,  12, 5, 6,  11, 0,  14, 9,  2,
                7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
                2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5, 6,  11
        }
};

void DES::ip(const bitset<SIZE::BLOCK> &input, bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r) {

    for (int i = 0; i < r.size(); i++) {
        r[i] = input[ipTable[i] - 1];
    }

    for (int i = 0; i < l.size(); i++) {
        l[i] = input[ipTable[i + l.size()] - 1];
    }

}

void DES::turnLR(bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r, const bitset<SIZE::CODE> &key) {

    bitset<SIZE::CODE> er;
    bitset<SIZE::CODE> code;

    for (int i = 0; i < er.size(); i++) {
        ///32位扩展为48位
        er[i] = r[eTable[i] - 1];
    }

    ///进行异或
    er ^= key;

    ///进行s变换

    bitset<4> col; ///列
    bitset<2> row; ///行

    bitset<SIZE::HALF_BLOCK> sr;
    for (int i = 0; i < 8; i++) {
        row[0] = er[6 * i];
        row[1] = er[6 * i + 5];

        for (int j = 0; j < 4; j++) {
            col[j] = er[6 * i + 1 + j];
        }

        ///将6位转化为4位
        bitset<4> tmp((unsigned long long int) sTable[i][row.to_ulong() * 16 + col.to_ulong()]);

        ///将结果保存到sr中
        for (int j = 0; j < tmp.size(); j++) {
            sr[4 * i + j] = tmp[j];
        }
    }


    ///进行p变换
    bitset<SIZE::HALF_BLOCK> pr;
    for (int i = 0; i < pr.size(); i++) {
        pr[i] = sr[pTable[i] - 1];
    }

    ///进行最终的L'=R ,R' = L^f(R,K)

//    l^=pr;

    ///执行了交换策略
    bitset<HALF_BLOCK> tmpl;
    tmpl = l;
    l = r;
    r = tmpl ^ pr;

}

bitset<DES::SIZE::HALF_BLOCK> DES::f(bitset<SIZE::HALF_BLOCK> &in, const bitset<SIZE::CODE> &key) {
    bitset<SIZE::CODE> ein;
    for (int i = 0; i < in.size(); i++) {
        ein[i] = in[eTable[i] - 1];
    }

    ein ^= key;

    bitset<SIZE::HALF_BLOCK> sein;
    bitset<4> col; ///列
    bitset<2> row; ///行



    for (int i = 0; i < 8; i++) {
        row[0] = ein[6 * i];
        row[1] = ein[6 * i + 5];

        for (int j = 0; j < 4; j++) {
            col[j] = ein[i + 1 + j];
        }

        ///将6位转化为4位
        bitset<4> tmp((unsigned long long int) sTable[i][row.to_ulong() * 16 + col.to_ulong()]);

        ///将结果保存到sr中
        for (int j = 0; j < 4; j++) {
            sein[4 * i + j] = tmp[j];
        }
    }

    bitset<SIZE::HALF_BLOCK> psein;
    for (int i = 0; i < psein.size(); i++) {
        psein[i] = sein[pTable[i] - 1];
    }

    return psein;
}


void DES::keyTurn(const bitset<SIZE::BLOCK> &key, bitset<SIZE::HALF_KEY> &l, bitset<SIZE::HALF_KEY> &r) {
    for (int i = 0; i < r.size(); i++) {
        r[i] = key[pc1Table[i] - 1];
    }

    for (int i = 0; i < l.size(); i++) {
        l[i] = key[pc1Table[i + l.size()] - 1];
    }

}

void DES::leftMove(bitset<SIZE::HALF_KEY> &l, bitset<SIZE::HALF_KEY> &r, int step) {

    ///@param step 层数 1~16
    int move = leftShift[step - 1];

    l <<= move;
    r <<= move;
}

void DES::compressKey(const bitset<SIZE::HALF_KEY> &l, const bitset<SIZE::HALF_KEY> &r, bitset<SIZE::CODE> resKey) {

    bitset<SIZE::KEY> tmp;
    ///合并
    for (int i = 0; i < r.size(); i++) {
        tmp[i] = r[i];
    }
    for (int i = 0; i < l.size(); i++) {
        tmp[i + l.size()] = l[i];
    }

    ///进行压缩置换
    for (int i = 0; i < resKey.size(); i++) {
        resKey[i] = tmp[pc2Table[i] - 1];
    }
}

bitset<DES::SIZE::BLOCK> DES::encrypt(const bitset<SIZE::BLOCK> &in, const bitset<SIZE::BLOCK> &key) {
    bitset<SIZE::HALF_KEY> keyl, keyr;
    bitset<SIZE::HALF_BLOCK> l, r;
    bitset<SIZE::CODE> keynth;
    bitset<SIZE::BLOCK> res;

    ip(in, l, r);
    for (int i = 1; i <= 16; i++) {
        keynth = getKey(i, key);
//        cout<<keynth.to_ulong()<<endl;
        turnLR(l, r, keynth);
        if (i == 16) {
            swap(l, r);
        }
    }
    finalIp(l, r, res);
    return res;
}

bitset<DES::SIZE::BLOCK> DES::decrypt(const bitset<SIZE::BLOCK> &in, const bitset<SIZE::BLOCK> &key) {
//    bitset<SIZE::HALF_KEY> keyl,keyr;
    bitset<SIZE::HALF_BLOCK> l, r;
    bitset<SIZE::CODE> keynth;
    bitset<SIZE::BLOCK> res;

    ip(in, l, r);
//    keyTurn(key,keyl,keyr);
    for (int i = 16; i >= 1; i--) {
        keynth = getKey(i, key);

//        cout<<i<<": "<<keynth.to_ulong()<<endl;
        turnLR(l, r, keynth);
        if (i == 1) {
            swap(l, r);
        }
    }
    finalIp(l, r, res);
    return res;
}

void DES::finalIp(bitset<SIZE::HALF_BLOCK> &l, bitset<SIZE::HALF_BLOCK> &r, bitset<SIZE::BLOCK> &res) {

    bitset<SIZE::BLOCK> tmp;
    for (int i = 0; i < res.size(); i++) {
        if (ppTable[i] <= 32) {
            res[i] = r[ppTable[i] - 1];
        } else {
            res[i] = l[ppTable[i] - 32 - 1];
        }
    }

}

bitset<DES::SIZE::CODE> DES::getKey(int step, const bitset<SIZE::BLOCK> key) {
    ///step 0~15
    bitset<SIZE::CODE> res;
    int n = step - 1;

    ///56bit
    bitset<SIZE::KEY> kkey;
    size_t klen = key.size(), rlen = res.size();//分别为56和48

    ///ipc1
    for (int i = 0; i < kkey.size(); i++) {
        kkey[i] = key[pc1Table[i] - 1];
    }

    ///循环移位
    for (int i = 0; i <= n; i++) {
        for (int j = 0; j < leftShift[i]; j++) {
            ///将密钥循环位暂存在res中
            res[rlen - leftShift[i] + j] = kkey[klen - leftShift[i] + j];
            res[rlen / 2 - leftShift[i] + j] = kkey[klen / 2 - leftShift[i] + j];
        }

        ///移位
        kkey <<= leftShift[i];

        ///写回
        for (int j = 0; j < leftShift[i]; j++) {
            kkey[klen / 2 + j] = res[rlen - leftShift[i] + j];
            kkey[j] = res[rlen / 2 - leftShift[i] + j];
        }
    }

    ///压缩置换
    for (int i = 0; i < res.size(); i++) {
        res[i] = kkey[pc2Table[i] - 1];
    }
    return res;
}

string DES::toString(const bitset<SIZE::BLOCK> block) {
    string res;
    res.clear();
    for (int i = 0; i < block.size() / 4; i++) {
        bitset<4> hexBit;
        for (int j = 0; j < 4; j++) {
            hexBit[j] = block[4 * i + j];
        }
        res += bit4ToChar(hexBit);
    }
    reverse(res.begin(), res.end());
    return res;

}

char DES::bit4ToChar(const bitset<4> bit4) {
    auto idx = bit4.to_ulong();
    return bitTable[idx];
}


#endif //DES_DES_HPP
