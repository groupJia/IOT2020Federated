import numpy as np
import time
import sys
import datetime
import os
from scipy.sparse import csr_matrix
import re
import random
import hashlib
import hmac
import random
import pickle
import pypbc
import gmpy
from Crypto.Cipher import AES
import json
import string
from web3 import Web3
from pypbc import *
import gmpy2
from gmpy2 import mpz
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware
import struct
from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider

# w3 = Web3(HTTPProvider('http://localhost:8540'))
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8540"))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
# w3 = Web3(Web3.WebsocketProvider("ws://127.0.0.1:8650"))


g=mpz(2141434891434191460597654106285009794456474073127443963580690795002163321265105245635441519012876162226508712450114295048769820153232319693432987768769296824615642594321423205772115298200265241761445943720948512138315849294187201773718640619332629679913150151901308086084524597187791163240081868198195818488147354220506153752944012718951076418307414874651394412052849270568833194858516693284043743223341262442918629683831581139666162694560502910458729378169695954926627903314499763149304778624042360661276996520665523643147485282255746183568795735922844808611657078638768875848574571957417538833410931039120067791054495394347033677995566734192953459076978334017849678648355479176605169830149977904762004245805443987117373895433551186090322663122981978369728727863969397652199851244115246624405814648225543311628517631088342627783146899971864519981709070067428217313779897722021674599747260345113463261690421765416396528871227)
p=mpz(3268470001596555685058361448517594259852327289373621024658735136696086397532371469771539343923030165357102680953673099920140531685895962914337283929936606946054169620100988870978124749211273448893822273457310556591818639255714375162549119727203843057453108725240320611822327564102565670538516259921126103868685909602654213513456013263604608261355992328266121535954955860230896921190144484094504405550995009524584190435021785232142953886543340776477964177437292693777245368918022174701350793004000567940200059239843923046609830997768443610635397652600287237380936753914127667182396037677536643969081476599565572030244212618673244188481261912792928641006121759661066004079860474019965998840960514950091456436975501582488835454404626979061889799215263467208398224888341946121760934377719355124007835365528307011851448463147156027381826788422151698720245080057213877012399103133913857496236799905578345362183817511242131464964979)
q=mpz(93911948940456861795388745207400704369329482570245279608597521715921884786973)

sys.setrecursionlimit(10000)
model = AES.MODE_ECB

#读取broker密钥
f_broker_key = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/broker_key.txt','rb')
broker_key=pickle.load(f_broker_key)
print('broker_key',broker_key)


def func_qqqq(pairing, Zr,x,beta,xishu):
    k=beta
    for i in range(len(xishu)):
        k=k+(xishu[i]*int(x)**(len(xishu)-i))
    y =Element(pairing, Zr, value=k)
    return y

def KeyGen(pairing,gg,d_number):
    # params = Parameters(qbits=512, rbits=160)  # type a
    # pairing = Pairing(params)
    # 从G2中取一个随机数，并初始化一个元素，也就是生成元。
    # g = Element.random(pairing, G2)  # 1024byte
    # 生成随机指数
    alp = Element.random(pairing, Zr)
    # print('alp',alp)
    beta = Element.random(pairing, Zr)
    r = Element.random(pairing, Zr)
    g1 = Element(pairing, G2, value=gg ** alp)
    g2 = Element(pairing, G2, value=gg ** beta)
    xishu=[]
    for i in range(d_number):
        xishu.append(Element.random(pairing, Zr))
    # xishu1 = Element.random(pairing, Zr)
    # xishu2 = Element.random(pairing, Zr)
    # xishu3 = Element.random(pairing, Zr)
    q1 = func_qqqq(pairing, Zr, 1, beta, xishu)
    gq1 = Element(pairing, G2, value=gg ** q1)
    q2 = func_qqqq(pairing, Zr, 2, beta, xishu)
    gq2 = Element(pairing, G2, value=gg ** q2)
    q3 = func_qqqq(pairing, Zr, 3, beta, xishu)
    gq3 = Element(pairing, G2, value=gg ** q3)
    ####################生成公钥和私钥
    # 公钥
    # PK = [gg, g1, g2, gq1, gq2, gq3]
    # PK = [gg, g1, g2, gq1]
    PK = [gg, g1, g2]
    for k in range(d_number):
        PK.append(xishu[k])
    sk0_1 = Element(pairing, G2, value=g2 ** (alp + r))
    t = get_random_prime(10)
    t0 = int(t).to_bytes(length=10, byteorder='big', signed=True)
    hash_value_t0 = Element.from_hash(pairing, Zr, t0)
    qt0 = func_qqqq(pairing, Zr, hash_value_t0, beta, xishu)
    sk0_2 = Element(pairing, G2, value=(gg ** qt0) ** r)
    sk0_3 = Element(pairing, G2, value=gg ** r)
    sk0_4 = t
    SK0 = [sk0_1, sk0_2, sk0_3, sk0_4]
    return PK,SK0,xishu,beta


def Encrypt(PK,M,tagset,pairing,beta,xishu,gg):
    # s = Element.random(pairing, Zr)
    s=Element.random(pairing, Zr)
    # s=get_random_prime(10)
    # print('s',s)
    PB = Element( pairing, GT )
    # print("----PK[0]",PK[0])
    # print(type(PK[0]))
    # print("gg",gg)
    PB = pairing.apply(PK[1], PK[2])
    PB=Element(pairing, GT, value=PB**s)
    ct1=Element(pairing, GT, value=M*PB)
    # print('yyyyes')
    # ct2 = Element( pairing, G2 )
    ct2=Element(pairing, G2, value=gg ** s)
    CT=[ct1,ct2]
    # print('CT',CT)
    # print('yes')
    for i in range(len(tagset)):
        tag=int(tagset[i]).to_bytes(length=10, byteorder='big', signed=True)
        hash_value = Element.from_hash(pairing, Zr, tag)
        qt = func_qqqq(pairing, Zr, hash_value,beta,xishu)
        cti= Element(pairing, G2, value=(PK[0] ** qt) ** s)
        CT.append(cti)
    return CT


def punc(PK,SK,tag,beta,xishu):
    ###此论文只punc一次
    labdapie = Element.random(pairing, Zr)
    r0 = Element.random(pairing, Zr)
    r1 = Element.random(pairing, Zr)

    sk0pie1=Element(pairing, G2, value= SK[0]*(PK[2]**(r0-labdapie)))
    tagbyte = int(SK[3]).to_bytes(length=10, byteorder='big', signed=True)
    hash_value = Element.from_hash(pairing, Zr, tagbyte)
    qt0 = func_qqqq(pairing, Zr, hash_value,beta,xishu)
    sk0pie2 = Element(pairing, G2, value=(SK[1]*((PK[0]**qt0)**r0)))
    sk0pie3=Element(pairing, G2, value=SK[2]*(PK[0]**r0))
    sk0pie4=SK[3]
    SK0new=[sk0pie1,sk0pie2,sk0pie3,sk0pie4]
    SK_punc = []
    SK_punc.append(SK0new)
    #sk1
    sk1pie1=Element(pairing, G2, value=PK[2]**(labdapie+r1))
    tagbyte = int(tag).to_bytes(length=10, byteorder='big', signed=True)
    hash_value = Element.from_hash(pairing, Zr, tagbyte)
    qt1 = func_qqqq(pairing, Zr, hash_value,beta,xishu)
    sk1pie2=Element(pairing, G2, value=(PK[0]**qt1)**r1)
    sk1pie3=Element(pairing, G2, value=PK[0]**r1)
    sk1pie4=tag
    SK1=[sk1pie1,sk1pie2,sk1pie3,sk1pie4]
    SK_punc.append(SK1)
    return SK_punc



d_number=9


######################生成公私密钥和相应参数
brokernumber=14
Public_parameter_set=[]
SK_set=[]
SK_set_b1={}
SK_set_b2={}
SK_set_b3={}
SK_set_b4={}
SK_set_b5={}
# SK_set_b6={}

##########b1
params = Parameters(qbits=512, rbits=160)  # type a
pairing = Pairing(params)
gg = Element.random(pairing, G2)
print('initial gg',gg)
list1=[]
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list1=[PK,SK0,xishu,beta]
Public_parameter_set.append(list1)
#存成字典

sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b2[1]=sk_set[0]
# SK_set_b3[1]=sk_set[1]
# SK_set_b4[1]=sk_set[2]
# SK_set_b5[1]=sk_set[3]
# SK_set_b6[1]=sk_set[4]

#########b2

#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list2=[PK,SK0,xishu,beta]
Public_parameter_set.append(list2)
#存成字典
sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b1[2]=sk_set[0]
# SK_set_b3[2]=sk_set[1]
# SK_set_b4[2]=sk_set[2]
# SK_set_b5[2]=sk_set[3]
# SK_set_b6[2]=sk_set[4]


##########b3
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list3=[PK,SK0,xishu,beta]
Public_parameter_set.append(list3)
#存成字典
sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b1[3]=sk_set[0]
# SK_set_b2[3]=sk_set[1]
# SK_set_b4[3]=sk_set[2]
# SK_set_b5[3]=sk_set[3]
# SK_set_b6[3]=sk_set[4]


###########b4
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list4=[PK,SK0,xishu,beta]
Public_parameter_set.append(list4)
#存成字典
sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b1[4]=sk_set[0]
# SK_set_b2[4]=sk_set[1]
# SK_set_b3[4]=sk_set[2]
# SK_set_b5[4]=sk_set[3]
# SK_set_b6[4]=sk_set[4]



############b5
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list5=[PK,SK0,xishu,beta]
Public_parameter_set.append(list5)
#存成字典
sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b1[5]=sk_set[0]
# SK_set_b2[5]=sk_set[1]
# SK_set_b3[5]=sk_set[2]
# SK_set_b4[5]=sk_set[3]
# SK_set_b6[5]=sk_set[4]



############b6
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list6=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list6)
#存成字典
sk_set=[]
for i in range(brokernumber):
    tagnew=get_random_prime(20)
    SK_punc=punc(PK,SK0,tagnew,beta,xishu)
    sk_set.append(SK_punc)

# SK_set_b1[6]=sk_set[0]
# SK_set_b2[6]=sk_set[1]
# SK_set_b3[6]=sk_set[2]
# SK_set_b4[6]=sk_set[3]
# SK_set_b5[6]=sk_set[4]


############b7
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list7=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list7)


############b8
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list8=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list8)



############b9
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list9=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list9)





############b10
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list10=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list10)



############b11
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list11=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list11)



############b12
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list12=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list12)




############b11
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list13=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list13)



############b12
#########生成公私密钥和相应参数
PK,SK0,xishu,beta=KeyGen(pairing,gg,d_number)
list14=[PK,SK0,xishu,beta]
# print('list6',list6)
Public_parameter_set.append(list14)






print(Public_parameter_set)
############生成任务索引

#####################每个broker生成明文
kw=["Accounting", "Financial_Planning", "Human_Resource", "Management Consulting", "Data Entry", "Project Management", "Transcription", "Web Research", "Customer Service", "Technical Support", "Data Extraction", "Data Visualization", "Machine Learning", "Animation", "Audio Production", "Motion Graphics", "Photography", "Information Security", "Contract Law","Criminal Law"]
for i in range(len(kw)):
    kw[i]=kw[i].encode(('utf-8'))
    if len(kw[i])>30:
        print("overflow")
    kw[i]=int.from_bytes(kw[i], byteorder='big')

KWWW=kw[0:3]
print('KWWW',KWWW)
###############################################################任务数量##############################
each_kw_task_num=12
broker_task_M=[]
for i in range(brokernumber):
    t={}
    for w in KWWW:
        t[w]=[]
        for j in range(each_kw_task_num):
            PK1= Public_parameter_set[i][0]
            M = Element(pairing, GT)
            M = pairing.apply(PK1[0], PK1[0])
            s = random.randint(10, 1000000000)
            M = Element(pairing, GT, value=M ** s)
            t[w].append(M)
    broker_task_M.append(t)
print(broker_task_M)
print('len(broker_task_M)',len(broker_task_M))

################################################## 初始化本地kw状态索引

broker_local_kw_state_index=[]
for i in range(len(broker_key)):
    state={}
    print('i',i)
    for kw1 in broker_task_M[i]:
        state[kw1]=0
    broker_local_kw_state_index.append(state)


Each_broker_tag_num=[]
for i in range(brokernumber):
    Each_broker_tag_num.append(d_number)

def pad(a):
    b=hex(a)
    b=b[2:]
    return "0"*(64-len(b))+b
#################################建立关键字-任务索引
On_chain_task_index={}

on_chain_hash_index={}
start1 = datetime.datetime.now()
for i in range(brokernumber):
    for kw in broker_task_M[i]:
        a=broker_key[i][1]
        ac = ((mpz(kw) % q) * (mpz(a) % q)) % q
        gac = gmpy2.powmod(g, ac, p)
        trap=hex(int(gac))
        for block in range(len(broker_task_M[i][kw])):
            trapdoor = trap + pad(broker_local_kw_state_index[i][kw])
            broker_local_kw_state_index[i][kw]=broker_local_kw_state_index[i][kw]+1
            label = (Web3.keccak(hexstr=trapdoor)).hex()
            label=Web3.toBytes(hexstr=label)
            # print('type(label)',type(label))
            PK, SK0, xishu, beta=Public_parameter_set[i]
            #生成tag
            tagset = []
            for sss in range(Each_broker_tag_num[i]):
                t = get_random_prime(10)
                tagset.append(t)

            CT = Encrypt(PK, broker_task_M[i][kw][block], tagset, pairing, beta, xishu,gg)
            CTbyte = str.encode(str(CT[1]))
            Chash = Web3.keccak(CTbyte)
            PP = bytes(a ^ b for a, b in zip(label, Chash))
            On_chain_task_index[label] = PP
            on_chain_hash_index[Chash] = []
            for cti in range(len(CT)):
                bytect1 = str.encode(str(CT[cti]))
                on_chain_hash_index[Chash].append(bytect1)
            for tagci in range(Each_broker_tag_num[i]):
                ctag=int(tagset[tagci]).to_bytes(length=10, byteorder='big', signed=True)
                on_chain_hash_index[Chash].append(ctag)
            CT = []
end1 = datetime.datetime.now()
print('On_chain_task_index',On_chain_task_index)
print('on_chain_hash_index',on_chain_hash_index)
print("build index time----------local", end1-start1)


# def lagrange(x, num_points, x_test):
#     # 所有的基函数值，每个元素代表一个基函数的值
#     l = np.zeros(shape=(num_points, ))
#
#     # 计算第k个基函数的值
#     for k in range(num_points):
#         l[k] = 1
#         for k_ in range(num_points):
#             if k != k_:
#                 if (x[k]-x[k_])!=0:
#                     l[k] = l[k]*(x_test-x[k_])/(x[k]-x[k_])
#                 else:
#                     print('fenmy equal 0')
#             else:
#                 pass
#     # print(l)
#     return l
#
#
#
#
# def decrypt(PK,SK_punc,CT,tagset):
#     SK1=SK_punc[0]
#     # print('SK1',SK1)
#     SK2=SK_punc[1]
#     #计算系数w（d=3,一共四个系数）
#     tagSet1=[]
#     tagSet2=[]
#     for i in range(len(tagset)):
#         tagSet1.append(tagset[i])
#         tagSet2.append(tagset[i])
#     tagSet1.insert(0, SK_punc[0][3])
#     tagSet2.insert(0, SK_punc[1][3])
#     taghashset1=[]
#     for i in range(len(tagSet1)):
#         byt=int(tagSet1[i]).to_bytes(length=10, byteorder='big', signed=True)
#         hash_value = Element.from_hash(pairing, Zr, byt)
#         hash_value = int(hash_value)
#         taghashset1.append(hash_value)
#     taghashset2=[]
#     for i in range(len(tagSet2)):
#         byt=int(tagSet2[i]).to_bytes(length=10, byteorder='big', signed=True)
#         hash_value = Element.from_hash(pairing, Zr, byt)
#         hash_value=int(hash_value)
#         taghashset2.append(hash_value)
#     # 计算系数w（d=3,一共四个系数）
#     ####顺序w*,w1,w2,w3
#     wset1 = lagrange(taghashset1, len(taghashset1), 0)
#     wset2 = lagrange(taghashset2, len(taghashset2), 0)
#     ##计算Z1
#     print('wset1', wset1)
#     print('wset2', wset2)
#     wwse1=[]
#     wwse2=[]
#     for i in wset1:
#         wwse1.append(round(i, 15))
#     for i in wset2:
#         wwse2.append(round(i, 15))
#     print('wwse1',wwse1)
#     print('wwse2', wwse2)
#     ww1=[]
#     ww2=[]
#     mutiply=10000000000000000
#     for i in wwse1:
#         ww1.append(int(i*mutiply))
#     for i in wwse2:
#         ww2.append(int(i*mutiply))
#     print(ww1)
#     print(ww2)
#     #####compute z1
#     pup=pairing.apply(SK_punc[0][0], CT[1])
#     pup=Element(pairing, GT, value=pup**mutiply)
#     ji=Element(pairing, G2, value=(CT[2]**ww1[1])+(CT[3]**ww1[2])+(CT[4]**ww1[3]))
#     pdown1 = pairing.apply(SK_punc[0][2], ji)
#     p=pairing.apply(SK_punc[0][1], CT[1])
#     pdown2=Element(pairing, GT, value=p**ww1[0])
#     Z1=Element(pairing, GT, value=pup*((pdown1*pdown2)**(-1)))
#
#     #计算Z2
#     pup = pairing.apply(SK_punc[1][0], CT[1])
#     pup = Element(pairing, GT, value=pup ** mutiply)
#     ji = Element(pairing, G2, value=CT[2] ** ww2[1] + CT[3] ** ww2[2] + CT[4] ** ww2[3])
#     pdown1 = pairing.apply(SK_punc[1][2], ji)
#     p = pairing.apply(SK_punc[1][1], CT[1])
#     pdown2 = Element(pairing, GT, value=p ** ww2[0])
#     Z2 = Element(pairing, GT, value=pup*((pdown1*pdown2)**(-1)))
#     M=Element(pairing, GT, value=CT[0]*((Z1*Z2)**(-1)))
#     print(M)
#     return M
#


abi_build_index="""
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "p",
				"type": "bytes"
			}
		],
		"name": "setP",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "chash",
				"type": "bytes32[]"
			},
			{
				"name": "t6",
				"type": "bytes[]"
			},
			{
				"name": "t7",
				"type": "bytes[]"
			},
			{
				"name": "t8",
				"type": "bytes[]"
			},
			{
				"name": "t9",
				"type": "bytes[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "set_hash_Cipher_index3",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "retCA",
				"type": "bytes32"
			}
		],
		"name": "get_ciphtertext",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "chash",
				"type": "bytes32[]"
			},
			{
				"name": "ct1",
				"type": "bytes[]"
			},
			{
				"name": "ct2",
				"type": "bytes[]"
			},
			{
				"name": "ct31",
				"type": "bytes[]"
			},
			{
				"name": "ct32",
				"type": "bytes[]"
			},
			{
				"name": "ct33",
				"type": "bytes[]"
			},
			{
				"name": "ct34",
				"type": "bytes[]"
			},
			{
				"name": "ct35",
				"type": "bytes[]"
			},
			{
				"name": "ct36",
				"type": "bytes[]"
			},
			{
				"name": "ct37",
				"type": "bytes[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "set_hash_Cipher_index1",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "auinfo",
				"type": "bytes[]"
			}
		],
		"name": "updateauthorization",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "task_hash_index",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "returnCA",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "chash",
				"type": "bytes32[]"
			},
			{
				"name": "ct38",
				"type": "bytes[]"
			},
			{
				"name": "ct39",
				"type": "bytes[]"
			},
			{
				"name": "t1",
				"type": "bytes[]"
			},
			{
				"name": "t2",
				"type": "bytes[]"
			},
			{
				"name": "t3",
				"type": "bytes[]"
			},
			{
				"name": "t4",
				"type": "bytes[]"
			},
			{
				"name": "t5",
				"type": "bytes[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "set_hash_Cipher_index2",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "token",
				"type": "bytes32[]"
			},
			{
				"name": "value",
				"type": "bytes32[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "set_taskindex",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "cipher",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "hash_Cipher_index",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "get_returnCA",
		"outputs": [
			{
				"name": "",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "x",
				"type": "uint256"
			}
		],
		"name": "toBytes",
		"outputs": [
			{
				"name": "b",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "authori",
				"type": "bytes"
			}
		],
		"name": "setauthorize",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "authorization",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "retCA",
				"type": "bytes32"
			}
		],
		"name": "set_ciphtertext",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			},
			{
				"name": "fbpie",
				"type": "uint256"
			}
		],
		"name": "get_searchtoke",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "get_returnonetimeC",
		"outputs": [
			{
				"name": "",
				"type": "bytes[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "pp",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "a",
				"type": "bytes"
			},
			{
				"name": "b",
				"type": "bytes32"
			}
		],
		"name": "concat",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "searchfbpie",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "g",
				"type": "bytes"
			},
			{
				"name": "x",
				"type": "uint256"
			},
			{
				"name": "p",
				"type": "bytes"
			}
		],
		"name": "expmod",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "returnC",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "searchtok",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "get_returnCeachget",
		"outputs": [
			{
				"name": "",
				"type": "bytes[][]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			},
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "returnCeachget",
		"outputs": [
			{
				"name": "",
				"type": "bytes"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "tok",
				"type": "uint256"
			}
		],
		"name": "get_authorize",
		"outputs": [
			{
				"name": "",
				"type": "bytes[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "task_index",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
"""

from_account = w3.toChecksumAddress("0x3c62Aa7913bc303ee4B9c07Df87B556B6770E3fC")
abi_build_index = json.loads(abi_build_index)
store_var_contract = w3.eth.contract(
   address=w3.toChecksumAddress('0xa2a93c5f81f859983a2c978f854FCD08e43f968E'),
   abi=abi_build_index)
phex = hex(int(p))


##################上传任务索引到blockchain

############################向blockchain添加任务索引##################
#####################################################向blockchain传GGGGGGG-hash索引
t_start=datetime.datetime.now()
batchtoken=[]
batchhash=[]
times=0
print('total task index number',len(On_chain_task_index))
batchint=int(len(On_chain_task_index)/400)
batchyue=len(On_chain_task_index)%400
int_times=0
for token in On_chain_task_index:
    times=times+1
    batchtoken.append(token)
    batchhash.append(On_chain_task_index[token])
    if times==400 and int_times<batchint:
        int_times=int_times+1
        times=0
        # print(len(batchtoken))
        tx_hash=store_var_contract.functions.set_taskindex(batchtoken, batchhash,400).transact({
            "from": from_account,
            "gas": 80000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        batchtoken=[]
        batchhash=[]
    if int_times==batchint and times==batchyue:
        tx_hash1=store_var_contract.functions.set_taskindex(batchtoken, batchhash, batchyue).transact({
            "from": from_account,
            "gas": 80000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash1)

#####################################################向blockchain传任务索引
#####################################################向blockchain传hash-ciphter索引


batchtoken=[]
batchhash1=[]
batchhash2=[]
batchhash3=[]
batchhash4=[]
batchhash5=[]
batchhash6=[]
batchhash7=[]
batchhash8=[]
batchhash9=[]
batchhash10=[]
batchhash11=[]
tagS1=[]
tagS2=[]
tagS3=[]
tagS4=[]
tagS5=[]
tagS6=[]
tagS7=[]
tagS8=[]
tagS9=[]
times=0
eachbatchtasknum=200
batchint=int(len(on_chain_hash_index)/eachbatchtasknum)
# print(batchint)
batchyue=len(on_chain_hash_index)%eachbatchtasknum
# print('batchyue',batchyue)
int_times=0
tt = []
ttgas=[]
on_chain_inputlist=[]
for token in on_chain_hash_index:
    times=times+1
    batchtoken.append(token)
    batchhash1.append(on_chain_hash_index[token][0])
    batchhash2.append(on_chain_hash_index[token][1])
    batchhash3.append(on_chain_hash_index[token][2])
    batchhash4.append(on_chain_hash_index[token][3])
    batchhash5.append(on_chain_hash_index[token][4])
    batchhash6.append(on_chain_hash_index[token][5])
    batchhash7.append(on_chain_hash_index[token][6])
    batchhash8.append(on_chain_hash_index[token][7])
    batchhash9.append(on_chain_hash_index[token][8])
    batchhash10.append(on_chain_hash_index[token][9])
    batchhash11.append(on_chain_hash_index[token][10])
    tagS1.append(on_chain_hash_index[token][11])
    tagS2.append(on_chain_hash_index[token][12])
    tagS3.append(on_chain_hash_index[token][13])
    tagS4.append(on_chain_hash_index[token][14])
    tagS5.append(on_chain_hash_index[token][15])
    tagS6.append(on_chain_hash_index[token][16])
    tagS7.append(on_chain_hash_index[token][17])
    tagS8.append(on_chain_hash_index[token][18])
    tagS9.append(on_chain_hash_index[token][19])
    on_chain_inputlist

    if times==eachbatchtasknum and int_times<batchint:
        print('l')
        int_times=int_times+1
        times=0
        # print(len(batchtoken))
        tx_hash=store_var_contract.functions.set_hash_Cipher_index1(batchtoken, batchhash1,batchhash2,batchhash3,batchhash4,batchhash5,batchhash6,batchhash7,batchhash8,batchhash9,eachbatchtasknum).transact({
            "from": from_account,
            "gas": 900000000,
            "gasPrice": 0,
        })
        # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        # print('yes1')
        tt.append(tx_hash)
        tx_hash = store_var_contract.functions.set_hash_Cipher_index2(batchtoken,batchhash10,batchhash11,tagS1, tagS2, tagS3, tagS4,
                                                                     tagS5, eachbatchtasknum).transact({
            "from": from_account,
            "gas": 800000000,
            "gasPrice": 0,
        })
        tt.append(tx_hash)
        tx_hash = store_var_contract.functions.set_hash_Cipher_index3(batchtoken, tagS6, tagS7,tagS8,tagS9, eachbatchtasknum).transact({
            "from": from_account,
            "gas": 800000000,
            "gasPrice": 0,
        })
        tt.append(tx_hash)
        batchtoken=[]
        batchhash1=[]
        batchhash2 = []
        batchhash3 = []
        batchhash4 = []
        batchhash5 = []
        batchhash6=[]
        batchhash7=[]
        batchhash8 = []
        batchhash9 = []
        atchhash10 = []
        batchhash11 = []
        tagS1=[]
        tagS2=[]
        tagS3=[]
        tagS4=[]
        tagS5=[]
        tagS6 = []
        tagS7 = []
        tagS8 = []
        tagS9 = []

    if int_times==batchint and times==batchyue and batchyue!=0:
        tx_hash1=store_var_contract.functions.set_hash_Cipher_index1(batchtoken, batchhash1,batchhash2,batchhash3,batchhash4,batchhash5,batchhash6,batchhash7,batchhash8,batchhash9,batchyue).transact({
            "from": from_account,
            "gas": 900000000,
            "gasPrice": 0,
        })
        tt.append(tx_hash1)
        tx_hash2 = store_var_contract.functions.set_hash_Cipher_index2(batchtoken,batchhash10,batchhash11,tagS1, tagS2, tagS3, tagS4,
                                                                     tagS5,batchyue).transact({
            "from": from_account,
            "gas": 800000000,
            "gasPrice": 0,
        })
        tt.append(tx_hash2)
        tx_hash3 = store_var_contract.functions.set_hash_Cipher_index3(batchtoken, tagS6, tagS7,tagS8,tagS9,
                                                                       batchyue).transact({
            "from": from_account,
            "gas": 800000000,
            "gasPrice": 0,
        })
        tt.append(tx_hash3)
        # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash1)

for t in tt:
    tx=w3.eth.waitForTransactionReceipt(t)
    print(tx.status)
    ttgas.append(tx.gasUsed)
t_end=datetime.datetime.now()
print('time of task index initialzation', t_end-t_start)
print('on_chain_hash_index finish')

#
# for t in ttgas:
#     print(t)
#####################################################向blockchain传授权关系

#####################################将授权索引加入到blockchain

#############################生成授权关系
##################################################初始化授权索引

# authorization_index=[]
# for i in range(len(broker_key)):
#     au=[]
#     authorization_index.append(au)
#
# # start3=datetime.datetime.now()
# ##############################################################构建本地授权索引
# for i in range(brokernumber):
#     for j in range(brokernumber):
#         b = broker_key[j][2]
#         d = gmpy2.invert(b, q)
#         a = broker_key[i][1]
#         ab = ((mpz(a) % q) * (mpz(d) % q)) % q
#         gab = gmpy2.powmod(g, ab, p)
#         # print('gab',gab)
#         gabhex=hex(int(gab))
#         gabhex=gabhex[2:]
#         gabtian="0x"+"0"*(768-len(gabhex))+gabhex
#         authorization_index[j].append(gabtian)
#
# authoriztion={}
# for i in range(brokernumber):
#     authoriztion[broker_key[i][0]]=authorization_index[i]
#
#
# for aut in authoriztion:
#     print(len(authoriztion[aut]))
#
#
#
# # end3=datetime.datetime.now()
# print("authorization--local", authoriztion)
#
# #############
# print('on-chain authorization start')
# sumautho=0
#
# #####################################每个broker的授权索引，上传到blockchain上的

# tt=[]
# sumautho=0
# time_autor1=datetime.datetime.now()
# for aut in authoriztion:
#     print('aut',aut)
#     for j in range(len(authoriztion[aut])):
#         tx_hash11 = store_var_contract.functions.setauthorize(aut, authoriztion[aut][j]).transact({
#             "from": from_account,
#             "gas": 80000000,
#             "gasPrice": 0,
#         })
#         tt.append(tx_hash11)
# for t in tt:
#     tx_receipt = w3.eth.waitForTransactionReceipt(t)
#     sumautho=sumautho+tx_receipt.gasUsed
# print('authorization gas cost', sumautho)
# time_autor2=datetime.datetime.now()
# print('time of on-chain authorization:',time_autor2-time_autor1)
# kk=0
# for aut in authoriztion:
#     if kk==0:
#         cipher = store_var_contract.functions.get_authorize(aut).call()
#         print('len111(cipher)', len(cipher))
#         kk=kk+1
#
#
# print('total authorization gas cost',sumautho)
# # print("authorization--blockchain", end4-start3)
#
