# DES library
> Data encryption standard

## Brief


DES encrypt algorithm is Symmetric encryption.DES encryption library using c++ implement.When use in your project only include header file,and use public method.




## How to use
+ __include"DES.hpp"__   Original encrypt library
+ __include"fileDES.hpp__"   File encrypt library 

### DES:public function

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
+ __setInput__
	- @param: 



## Example



## Reference