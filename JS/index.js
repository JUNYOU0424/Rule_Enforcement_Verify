const CryptoJS = require('crypto-js')

const secretKey = '2b7e151628aed2a6abf7158809cf4f3c'
const packet_t = '000e39e3340000169c7cb00008004500006c000040003611623a16740741c9aefae326aa9e4300586098'
const header_t = '22.116.7.65201.174.250.22798984051517'
const inport_t = '00:16:9c:7c:b0:00'
const timestamp_t = 'Jan 23, 2011 13:00:00.845885000'
let p_src='',p_dst=''

Init()

function Init() {
    let VID = Generate_VID(inport_t, header_t, timestamp_t)
    let compress_key = Generate_SessionKey(VID, secretKey)
    let signature_key = Generate_SessionKey(compress_key, secretKey)
    let signature_info = Generate_SessionKey(VID + timestamp_t, secretKey)
    let packethash = Generate_PktHash(packet_t)
    p_src = packethash
    p_dst = packethash
    console.log('-----Init-----\n')
    console.log('VID\tLen:' + VID.length + '\n', VID)
    console.log('PacketHash\tLen:' + packethash.length + '\n', packethash)
    console.log('compress key\tLen:' + compress_key.length + '\n', compress_key)
    //console.log('SecretKey\tLen:' + secretKey.length + '\n', secretKey)
    //console.log('compress signature_key\tLen:' + signature_key.length + '\n', signature_key)
    //console.log('compress signature_info\tLen:' + signature_info.length + '\n', signature_info)
    console.log('-----Tagging-----\n')
    Tagging(VID, compress_key, packethash, signature_key, signature_info, 1)
    Verify(p_src,p_dst,VID)
}

function Tagging(VID, compress_key, packethash, signature_key, signature_info, i) {
    while (i != 4) {
        let SK_a = [],
            SK_b = [],
            alpha = [],
            tag = [],
            temp
        //console.log('Packet\tLen:' + packethash.length + '\n', packethash)
        temp = Generate_PktHash(packethash)
        p_dst += temp
        console.log('-----S'+i.toString()+'-----\n')
        console.log('PacketHash\tLen:' + temp.length + '\n', temp)
        packethash = temp
        SK_a[i] = Generate_SessionKey(VID + 0, secretKey)
        SK_b[i] = Generate_SessionKey(VID + 1, secretKey)
        alpha[i] = Generate_SessionKey(SK_a[i], secretKey)
        console.log('alpha\tLen:' + alpha[i].length + '\n', alpha[i])
        let a = Inner_Product(packethash, alpha[i])
        let b = Generate_SessionKey(SK_b[i], VID + i.toString())
        tag[i] = a + b
        console.log('tag\tLen:' + tag[i].length + '\n', tag[i])
        packethash += tag[i]
        i++
        Tagging(VID, compress_key, packethash, signature_key, signature_info, i)
    }
}

function Verify(p_src,p_dst,VID) {
    console.log('-----Verify-----\n')
    console.log('p_src len:'+p_src.length+'\n'+p_src+'\n')
    console.log('p_dst len:'+p_dst.length+'\n'+p_dst+'\n')
    for(let i=1;i<4;i++){
        let SK_a = [],
            SK_b = [],
            alpha = []
        SK_a[i] = Generate_SessionKey(VID + 0, secretKey)
        SK_b[i] = Generate_SessionKey(VID + 1, secretKey)
        alpha[i] = Generate_SessionKey(SK_a[i], secretKey)
        let a = Inner_Product(p_dst.slice(i*40,i*40+40),alpha[i])
        let b = Generate_SessionKey(SK_b[i], VID + i.toString())
        tag = a+b
        console.log('tag\n'+tag)
    }
}

function Inner_Product(a, b) {
    let result = 0
    let length = a.length>b.length?b.length:a.length
    for (let i = 0; i < length; i++) {
        result += parseInt(a[i], 16) * parseInt(b[i], 16)
    }
    return result.toString()
}

function Generate_VID(inport, header, timestamp) {
    let message = inport + header + timestamp
    return CryptoJS.SHA1(message).toString()
}

function Generate_PktHash(packet) {
    return CryptoJS.SHA1(packet).toString()
}

function Generate_SessionKey(message, key) {
    var iv = CryptoJS.enc.Hex.parse('2b7e151628aed2a6abf7158809cf4f3c')
    var option = {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
    }
    return CryptoJS.AES.encrypt(CryptoJS.enc.Hex.parse(message), CryptoJS.enc.Hex.parse(key), option).ciphertext.toString()
}