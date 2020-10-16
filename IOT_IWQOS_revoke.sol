pragma solidity >=0.4.22 <=0.6.0;
pragma experimental ABIEncoderV2;
contract federated{

    uint256 constant broker_number  = 14;
    mapping(uint256 =>  bytes []) public authorization;
    mapping(bytes32 => bytes32) public task_index;
    mapping(bytes32 => bytes32) public task_hash_index;
    mapping(bytes32 => bytes []) public hash_Cipher_index;

    uint256 public searchtok;
    bytes32 [] public cipher;
    uint public searchfbpie;
    bytes public pp;
    bytes [][] public returnC;
    bytes32 [] public returnCA;
    bytes  [][] public returnCeachget;
    bytes [] each_task_return;
    bytes32 state;
    bytes exp1;
    bytes concat1;
    bytes aut;
    bytes []onetimecipher;
    struct ct_andtag {
        bytes [] ct1;
        bytes [] ct2;
        bytes [] ct31;
        bytes [] ct32;
        bytes [] ct33;
        bytes [] ct34;
        bytes [] ct35;
        bytes [] t1;
        bytes [] t2;
        bytes [] t3;
        bytes [] t4;
        bytes [] t5;
    }

    // uint  [] public tag1;
    // uint  [] public tag2;
    // uint  [] public tag3;


    ////授权
    // function setauthorize(uint256 tok, bytes authori) public{
    //     authorization[tok].push(authori);
    // }
    function setauthorize(uint256 tok, bytes authori) public{
        authorization[tok].push(authori);
    }

    function updateauthorization(uint256 tok,bytes [] memory auinfo)public{

        authorization[tok]=auinfo;
    }


    function get_authorize(uint256 tok) public view returns (bytes[]){
        return authorization[tok];
    }


    //////G（）hash 索引
    function set_taskindex(bytes32 [] memory token, bytes32 [] memory value, uint len) public{
        for(uint i=0; i<len; i++) {
            bytes32 m=token[i];
            bytes32 n=value[i];
            // task_index[m]=n;
            task_hash_index[m]=n;
        }
    }
    // ///////hash任务index d=1
    // function set_hash_Cipher_index(bytes32 [] memory chash, bytes [] memory ct1, bytes [] memory ct2, bytes [] memory ct31,  bytes [] memory t1, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         hash_Cipher_index[chash[i]]=[ct1[i],ct2[i],ct31[i],t1[i]];
    //     }
    // }
    // ///////hash任务index d=3
    // function set_hash_Cipher_index(bytes32 [] memory chash, bytes [] memory ct1, bytes [] memory ct2, bytes [] memory ct31, bytes [] memory ct32, bytes [] memory ct33, bytes [] memory t1,bytes [] memory t2,bytes [] memory t3, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         hash_Cipher_index[chash[i]]=[ct1[i],ct2[i],ct31[i],ct32[i],ct33[i],t1[i],t2[i],t3[i]];
    //     }
    // }

    // /////hash任务index d=5
    // function set_hash_Cipher_index1(bytes32 [] memory chash, bytes [] memory ct1, bytes [] memory ct2, bytes [] memory ct31, bytes [] memory ct32, bytes [] memory ct33, bytes [] memory ct34,bytes [] memory ct35, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         // hash_Cipher_index[chash[i]]=[ct1[i],ct2[i],ct31[i],ct32[i],ct33[i],ct34[i],ct35[i]];
    //         hash_Cipher_index[chash[i]].push(ct1[i]);
    //         hash_Cipher_index[chash[i]].push(ct2[i]);
    //         hash_Cipher_index[chash[i]].push(ct31[i]);
    //         hash_Cipher_index[chash[i]].push(ct32[i]);
    //         hash_Cipher_index[chash[i]].push(ct33[i]);
    //         hash_Cipher_index[chash[i]].push(ct34[i]);
    //         hash_Cipher_index[chash[i]].push(ct35[i]);
    //     }
    // }
    // function set_hash_Cipher_index2(bytes32 [] memory chash, bytes [] memory t1, bytes [] memory t2, bytes [] memory t3, bytes [] memory t4, bytes [] memory t5, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         hash_Cipher_index[chash[i]].push(t1[i]);
    //         hash_Cipher_index[chash[i]].push(t2[i]);
    //         hash_Cipher_index[chash[i]].push(t3[i]);
    //         hash_Cipher_index[chash[i]].push(t4[i]);
    //         hash_Cipher_index[chash[i]].push(t5[i]);
    //     }
    // }
    /////hash任务index d=7
    // function set_hash_Cipher_index1(bytes32 [] memory chash, bytes [] memory ct1, bytes [] memory ct2, bytes [] memory ct31, bytes [] memory ct32, bytes [] memory ct33, bytes [] memory ct34,bytes [] memory ct35,bytes [] memory ct36,bytes [] memory ct37, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         // hash_Cipher_index[chash[i]]=[ct1[i],ct2[i],ct31[i],ct32[i],ct33[i],ct34[i],ct35[i]];
    //         hash_Cipher_index[chash[i]].push(ct1[i]);
    //         hash_Cipher_index[chash[i]].push(ct2[i]);
    //         hash_Cipher_index[chash[i]].push(ct31[i]);
    //         hash_Cipher_index[chash[i]].push(ct32[i]);
    //         hash_Cipher_index[chash[i]].push(ct33[i]);
    //         hash_Cipher_index[chash[i]].push(ct34[i]);
    //         hash_Cipher_index[chash[i]].push(ct35[i]);
    //         hash_Cipher_index[chash[i]].push(ct36[i]);
    //         hash_Cipher_index[chash[i]].push(ct37[i]);
    //     }
    // }
    // function set_hash_Cipher_index2(bytes32 [] memory chash, bytes [] memory t1, bytes [] memory t2, bytes [] memory t3, bytes [] memory t4, bytes [] memory t5,bytes [] memory t6,bytes [] memory t7, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         hash_Cipher_index[chash[i]].push(t1[i]);
    //         hash_Cipher_index[chash[i]].push(t2[i]);
    //         hash_Cipher_index[chash[i]].push(t3[i]);
    //         hash_Cipher_index[chash[i]].push(t4[i]);
    //         hash_Cipher_index[chash[i]].push(t5[i]);
    //         hash_Cipher_index[chash[i]].push(t6[i]);
    //         hash_Cipher_index[chash[i]].push(t7[i]);
    //     }
    // }
    ///hash任务index d=9
    function set_hash_Cipher_index1(bytes32 [] memory chash, bytes [] memory ct1, bytes [] memory ct2, bytes [] memory ct31, bytes [] memory ct32, bytes [] memory ct33, bytes [] memory ct34,bytes [] memory ct35,bytes [] memory ct36,bytes [] memory ct37, uint len)
    {
        for(uint i=0; i<len; i++) {
            // hash_Cipher_index[chash[i]]=[ct1[i],ct2[i],ct31[i],ct32[i],ct33[i],ct34[i],ct35[i]];
            hash_Cipher_index[chash[i]].push(ct1[i]);
            hash_Cipher_index[chash[i]].push(ct2[i]);
            hash_Cipher_index[chash[i]].push(ct31[i]);
            hash_Cipher_index[chash[i]].push(ct32[i]);
            hash_Cipher_index[chash[i]].push(ct33[i]);
            hash_Cipher_index[chash[i]].push(ct34[i]);
            hash_Cipher_index[chash[i]].push(ct35[i]);
            hash_Cipher_index[chash[i]].push(ct36[i]);
            hash_Cipher_index[chash[i]].push(ct37[i]);
        }
    }
    function set_hash_Cipher_index2(bytes32 [] memory chash, bytes [] memory ct38,bytes [] memory ct39, bytes [] memory t1, bytes [] memory t2, bytes [] memory t3, bytes [] memory t4, bytes [] memory t5,uint len)
    {
        for(uint i=0; i<len; i++) {
            hash_Cipher_index[chash[i]].push(ct38[i]);
            hash_Cipher_index[chash[i]].push(ct39[i]);
            hash_Cipher_index[chash[i]].push(t1[i]);
            hash_Cipher_index[chash[i]].push(t2[i]);
            hash_Cipher_index[chash[i]].push(t3[i]);
            hash_Cipher_index[chash[i]].push(t4[i]);
            hash_Cipher_index[chash[i]].push(t5[i]);
        }
    }
    function set_hash_Cipher_index3(bytes32 [] memory chash,bytes [] memory t6,bytes [] memory t7,bytes [] memory t8,bytes [] memory t9, uint len)
    {
        for(uint i=0; i<len; i++) {
            hash_Cipher_index[chash[i]].push(t6[i]);
            hash_Cipher_index[chash[i]].push(t7[i]);
            hash_Cipher_index[chash[i]].push(t8[i]);
            hash_Cipher_index[chash[i]].push(t9[i]);
        }
    }
    //search token
     //  计算幂
    function expmod(bytes g, uint256 x, bytes p) public view returns ( bytes) {
      require(p.length == 384,"unqualified length of p");
      require(g.length == 384,"unqualified length of g");
      bytes memory input = abi.encodePacked(bytes32(g.length),bytes32(0x20),bytes32(p.length),g,bytes32(x),p);
    //   bytes memory result = new bytes(384);
        bytes memory result = new bytes(384);
      bytes memory pointer = new bytes(384);
      assembly {
          if iszero(staticcall(sub(gas, 2000), 0x05, add(input,0x20), 0x380, add(pointer,0x20), 0x180 )) {
             revert(0, 0)
          }
      }
      for(uint i =0; i<12;i++) {
          bytes32 value;
          uint256 start = 32*i;
          assembly {
              value := mload(add(add(pointer,0x20),start))
          }
        //   return value;
          for(uint j=0;j<32;j++) {
              result[start+j] = value[j];
          }
      }
      return result;
    }



    function setP(bytes p) public{
        pp=p;
    }


    //int 转 bytes
    // function toBytes(uint256 x) public view returns (bytes32  b) {

    function toBytes(uint256 x) public view returns (bytes32  b) {

     return bytes32(x);

}



    //字符串拼接
    function concat(bytes a, bytes32 b) public view returns (bytes memory) {
        return abi.encodePacked(a,b);
    }


    function get_ciphtertext(bytes32 retCA) public{
        returnCeachget.push(hash_Cipher_index[retCA]);
    }

    function set_ciphtertext(bytes32 retCA)public {
        onetimecipher=hash_Cipher_index[retCA];
    }

    // function getbatch_ciphertext(bytes32 [] retCA, uint len)
    // {
    //     for(uint i=0; i<len; i++) {
    //         bytes32 t=retCA[i];
    //         bytes [] m=hash_Cipher_index[t];
    //         returnC.push(m);
    //     }

    // }

    //search function
     function get_searchtoke (uint256 tok, uint256 fbpie) public  {
         for(uint i=0;i<broker_number;i++){
             bytes memory autho=authorization[fbpie][i];
             //指数
             bytes memory exp=expmod(autho, tok, pp);
             uint256 c=0;
             bytes memory concatination=concat(exp,toBytes(c));

             bytes32  G1label=  keccak256(abi.encodePacked(concatination));
             bytes32 stop = 0x0;
             while (task_hash_index[G1label]!= stop){
                 bytes32  ciphertext=task_hash_index[G1label]^G1label;
                 returnCA.push(ciphertext);
                //  uint k=returnCA.length;
                //  for(uint m =0; m<k;m++)
                //  {
                //      returnC.push(hash_Cipher_index[ciphertext]);
                //  }
                 c=c+1;
                 concatination=concat(exp,toBytes(c));
                 G1label=keccak256(abi.encodePacked(concatination));

             }
         }
        //  return ctest;
     }






    function  get_returnCA() public view returns (bytes32[]){
        return returnCA;
    }

    function  get_returnonetimeC() public view returns (bytes []){
        return onetimecipher;
    }



    function  get_returnCeachget() public view returns (bytes [][]){
        return returnCeachget;
    }


    }