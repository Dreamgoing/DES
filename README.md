# DES library
> Data encryption standard

## Brief


DES encrypt algorithm is Symmetric encryption.DES encryption library using c++ implement.When use in your project only include header file,and use public method.




## How to use
+ __include"DES.hpp"__   Original encrypt library
+ __include"fileDES.hpp__"   File encrypt library 

### DES:public function
> DES is a static class, straightly use its public function.

+ __encrypt__ : 
	- @param: in,key (bitset<64>) 64bitset input and cipher
	- @return: ciphertext (bitset<64>) 64bitset result 

+ __decrypt__ :
	- @param: ciphertext ,key (bitset<64>) 64bitset ciphertext and cipher
	- @return: result (bitset<64>) 64bitset result

+ __toString__ :
	-  @brief: translate from bitset<64> to hexadecimal format
	-  @param: in (bitset<64>) 64bitset input
	-  @return: result (string) 

### fileDES:public function
> FileDES is a common class,need an instance to use it.

+ __setInput__
	- @brief: set input filepath and open it
	- @param: filepath(string)
	- @return: void
+ __setOutput__
	- @brief: set output filepath and mode and open it
	- @param: filepath(string), mode = 0 encrypt,mode = 1 decrypt.
	- @return: void

+ __setKey__
	- @brief: set cipher
	- @param: cipher(string)

+ __encryptFile__
	- @brief: encrypt input file and get ciphertext in output file

+ __decryptFile__
	- @brief: decrypt input file and get source file in output file




## Example

``` c++
    FileDES des;
    des.setInput("../data/input.txt"); ///your input file path
    des.setOutput("../data/encrypt.txt",0); ///your encrypt output file path
    des.setKey("123456"); ///your key
    des.encryptFile(); ///encrypt file
    des.setOutput("../data/decrypt.txt",1); ///your decrypt output file path
    des.decryptFile(); ///decrypt file
```

## Reference
[DATA ENCRYPTION STANDARD (DES) fips-46-3](https://wenku.baidu.com/view/e592bc630b1c59eef8c7b4c5.html)