
const C = {};

/**
 * 変換ライブラリ
 * Uint8Array,BinaryString,HEX,Base64,Base64url,int
 */
C.x = Object.freeze({
    $t:[],
    $g:{},
    init:function(){
        //16進数データの変換表を生成
        const c = "0123456789ABCDEF".split("");
        c.forEach(i=>c.forEach(y=>this.$t.push(i+y)));
        this.$t.forEach((v,i)=>{
            this.$g[v] = i;
            this.$g[v.toLowerCase()] = i;
        });
        return this
    },
    Error:function(msg){
        throw new Error("C.x." + msg);
    },
    TypeError:function(msg){
        throw new TypeError("C.x." + msg);
    },
    RangeError:function(msg){
        throw new RangeError("C.x." + msg);
    },
    /**
     * インスタンス判定
     * @param {prototype} t
     * @param {any} d - 判別対象
     */
    is:(t,d)=>d instanceof t,
    /**
     * Base64エンコード判定
     * @param {string} s
     * @returns {boolean}
     */
    isBase64: s=>/^[0-9A-Za-z+/]+=*$/.test(s),
    /**
     * Base64urlエンコード判定
     * @param {string} s
     * @returns {boolean}
     */
    isBase64url: s=>/^[0-9A-Za-z-_]+$/.test(s),
    /**
     * MAX_SAFE_INTEGER = 9007199254740991
     */
    isEmpty: x=>{
        return this.is(Array,x) ? !(x.length) :
        !(Object.keys(x).length);
    },
    MSI:Number.MAX_SAFE_INTEGER,
    /**
     * Uint8Array以外ならば変換
     * @param {(ArrayBuffer|TypedArray)} d
     * @returns {Uint8Array}
     */
    byte:function(d){
        return this.is(Uint8Array,d) ? d
            : this.is(ArrayBuffer,d) ? new Uint8Array(d)
            : d.buffer ? new Uint8Array(d.buffer)
            : this.TypeError("byte");
    },
    /**
     * HEX形式のデータを十進数の数値に変換
     * @param {string} hex - HEX形式のデータ 
     */
    hex_int:function(hex){
        const r = typeof hex === "number" ? 10 : 16;
        const int = parseInt(hex,r);
        if(int > this.MSI) this.RangeError("hex_int OVER MAX_SAFE_INTEGER");
        return int;
    },
    /**
     * 十進数の数値をHEX形式のデータに変換
     * @param {number} int - 数値
     * @param {boolean} upperCase - 大文字
     * @returns {string} - HEX文字列 
     */
    int_hex:function(int,upperCase=true){
        int = int * 1;
        if(int > this.MSI) this.RangeError("int_hex OVER MAX_SAFE_INTEGER");
        const hex = int.toString(16);
        return upperCase ? hex.toUpperCase() : hex;
    },
    /**
     * Uint8ArrayをHEXに変換する
     * @param {(Uint8Array|ArrayBuffer|TypedArray)} d
     * @returns {string} - HEX文字列
     */
    byte_hex:function(b,upperCase=true){
        b = this.byte(b);
        const c = [];
        b.forEach(v=>c.push(this.$t[v]));
        return upperCase ? c.join("").toUpperCase() : c.join("");
    },
    /**
     * HEXをUint8Arrayに変換する
     * @param {string} h - HEX文字列
     * @param {number} l - バイト長
     * @returns {Uint8Array}
     */
    hex_byte:function(h,l){
        if(l) h = h.padStart(l*2,"0");
        const q = h.split(/(..)/).filter(v=>v!=="");
        const c = q.map(v=>this.$g[v]);
        return new Uint8Array(c);
    },
    /**
     * Uint8Arrayをバイナリ文字列に変換する
     * @param {(Uint8Array|ArrayBuffer|TypedArray)} d
     * @returns {string} 
     */
    byte_bs:function(d){
        d = this.byte(d);
        return String.fromCharCode.apply(null,d);
    },
    /**
     * バイナリ文字列をUint8Arrayに変換する
     * @param {string} b
     * @returns {Uint8Array} 
     */
    bs_byte:function(b){
        const c = b.split("").map(v=>v.charCodeAt());
        return new Uint8Array(c);
    },
    /**
     * Base64形式をUint8Arrayに変換する
     * @param {string} a - Base64文字列
     * @param {boolean} v - 変種判定(Base64url) 
     * @returns {Uint8Array}
     */
    b64_byte:function(a,v){
        if(v&&this.isBase64url(a)) a = this.b64url_b64(a);
        const b = window.atob(a);
        return this.bs_byte(b);
    },
    /**
     * Uint8ArrayをBase64に変換する
     * @param {(Uint8Array|ArrayBuffer|TypedArray)} d 
     * @param {string} v - Base64変種の指定(url) 
     * @returns {string}
     */
    byte_b64:function(d,v){
        const b = this.byte_bs(d);
        const a = window.btoa(b);
        if(v==="url") return this.b64_b64url(a);
        return a;
    },
    /**
     * Base64またはBase64urlをUint8Arrayに変換する
     * @param {string} a - Base64,Base64url
     * @returns {Uint8Array}
     */
    base64_byte:function(a){
        if(this.isBase64(a)) return this.b64_byte(a);
        else return this.b64_byte(a,true);
    },
    /**
     * Base64のパディング
     */
    $padd64:s=>{
        let p=["","===","==","="];
        return s += p[s.length%4];
    },
    /**
     * Base64urlをBase64に変換する
     * @param {string} a - Base64url
     * @returns {string} - Base64
     */
    b64url_b64:function(a){
        return this.$padd64(
            a.replace(/-/g,"+").replace(/_/g,"/")
        );
    },
    /**
     * Base64をBase64urlに変換する
     * @param {string} a 
     * @returns {string} - Base64url
     */
    b64_b64url:function(a){
        return a.replace(/\+/g,"-").replace(/\//g,"_").replace(/=*$/,"");
    },
    /**
     * 文字列をUTF8エンコードしてBase64に変換する
     */
    utoa: str=>btoa(C.UTF8.encode(str)),
    /**
     * Base64をUTF8デコードして文字列に変換する
     */
    atou: b64=>C.UTF8.decode(atob(b64)),
    /**
     * blobを生成する
     * @param {Uint8Array} byte - データ 
     * @param {string} type - MIMEタイプ
     * @returns {blob}
     */
    blob:function(byte,type){
        if(!byte.indexOf) byte = [byte];
        return new Blob(byte,{type:type});
    },
    /**
     * blobからObjectURLを生成する
     * @param {blob} blob
     * @returns {object} - urlとrm() 
     */
    object:function(blob){
        return {
            url: URL.createObjectURL(blob),
            rm: function(){
                URL.revokeObjectURL(this.url);
            },
        };
    },
    /**
     * Base64エンコードされたデータからDataURLを作成する
     * @param {string} base64 
     * @param {string} MIME
     * @returns {string} - DataURL 
     */
    dataURL:function(base64,MIME){
        return ['data:',MIME,';base64,',base64].join("");
    },
    /**
     * Uint8Arrayを任意のエンコードに変換する
     * @param {Uint8Array} byte 
     * @param {string} encode - hex,base64,b64,b64url,bs
     * @returns {string}
     */
    byte_x:function(byte,encode){
        return encode === "hex" ? this.byte_hex(byte) :
        encode === "base64" ? this.byte_b64(byte) :
        encode === "b64" ? this.byte_b64(byte) :
        encode === "b64url" ? this.byte_b64(byte,"url") :
        encode === "bs" ? this.byte_bs(byte) :
        null;
    },
    /**
     * 複数のUint8Arrayを結合する
     * @param  {...Uint8Array} bytes
     * @returns {Uint8Array}
     */
    bytes_merge:function(...bytes){
        const d = [];
        bytes.forEach(c=>c.forEach(b=>d.push(b)));
        return new Uint8Array(d);
    },
}.init());


/**
 * 文字列のUTF8エンコードとデコード
 */
C.UTF8 = Object.freeze({
    /**
     * 文字列をUTF8にエンコードする
     * @param {String} string
     * @returns {Uint8Array}
     */
    encode: (function(){
        if(TextEncoder){
            const encoder = new TextEncoder();
            return str=>encoder.encode(str);
        };
        return function(str){
            return new Uint8Array(
                [...unescape(
                    encodeURIComponent(str)
                )].map(s=>s.codePointAt())
            );
        };
    }()),
    /**
     * UTF8データを文字列にデコードする
     * @params {(Uint8Array|ArrayBuffer|TypedArray)} utf8
     * @returns {String}
     */
    decode: (function(){
        if(TextDecoder){
            const decoder = new TextDecoder("utf-8");
            return utf8=>decoder.decode( C.x.byte(utf8) );
        };
        return function(utf8){
            utf8 = C.x.byte(utf8);
            return decodeURIComponent(
                escape( String.fromCodePoint(...utf8) )
            );
        };
    }()),
});



/**
 * 非同期 FileReader
 * @param {(Blob|File)} blob 
 * @param {String} type "ArrayBuffer","BinaryString","DataURL","Text"
 */
C.fileReader = function(blob,type){
    return new Promise(function(resolve,reject){
        const reader = new FileReader();
        reader.onload = x=>resolve(reader.result);
        reader.onerror = e=> reject(e);
        reader.onabort = e=> reject(e);
        if(type===ArrayBuffer) type = "ArrayBuffer";
        reader["readAs" + type](blob);
    });
};



/**
 * @constructor
 * @classdesc 
 */
class AESKey{
    constructor(){
        this.subtle = window.crypto.subtle;
        this.key;
    }
    async Error(msg){
        throw new Error("AESKey." + msg);
    }
    async init(key){
        if(!key || typeof key === "number"){
            await this.generate(key);
        }else if(typeof key === "string"){
            await this.import(key);
        }else if(key.byteLength){
            const l = key.byteLength;
            if([32].indexOf(l)+1){
                await this.import(key,"raw");
            }else{
                await this.Error("init byteLength")
            }
        }else if(key.k){
            await this.import(key)
        }else{
            await this.Error("init unknown key type")
        };
        return this;
    }
    async generate(length){
        if(this.key) await this.Error("generate");
        this.key = await this.subtle.generateKey(
            { name: "AES-GCM", length: length || 256 },
            true,
            ["encrypt","decrypt"]
        );
        return this;
    }
    async import(key,type="jwk",alg){
        var keyData;
        if(type==="raw") keyData = C.x.byte(key);
        else {
            keyData = {
                kty: "oct",
                k: key.k || key,
                alg: key.alg || alg || "A256GCM",
                ext: true
            };
        };
        this.key = await this.subtle.importKey(
            type,
            keyData,
            { name: "AES-GCM" },
            false,
            ["encrypt","decrypt"]
        );
        return this;
    }
    async export(type="jwk"){
        const d = await this.subtle.exportKey(
            type, this.key
        );
        return d;
    }
    async encrypt(data,ADD){
        //初期化ベクトル
        const iv = new Uint8Array(12);window.crypto.getRandomValues(iv);
        //オプション
        const options = { name:"AES-GCM", iv:iv };
        //追加認証データ
        if(ADD) options.additionalData = ADD;
        //暗号化
        const body = await this.subtle.encrypt(
            options, this.key, data
        );
        return { iv, body, ADD};
    }
    async decrypt(data,iv,ADD){
        //オプション
        const options = { name: "AES-GCM", iv: iv };
        //追加認証データ
        if(ADD) options.additionalData = ADD;
        //復号
        const d = await this.subtle.decrypt(
            options, this.key, data
        );
        return d;
    }
};

/**
 * @constructor
 * @classdesc 
 */
class RSAKey {
    constructor(){
        this.subtle = window.crypto.subtle;
        this.keys = {};
    }
    async Error(msg){
        throw new Error("RSAKey." + msg)
    }
    async init(key){
        if(!key) await this.generate();
        else if(key.kty === "RSA") await this.import(key);
        else if(typeof key === "string" && C.x.isBase64url(key)) await this.import(key,"n");
        else await this.Error(".init");
        return this;
    }
    async generate(){
        if(Object.keys(this.keys).length) return this;
        const EXPONENT = new Uint8Array([0x01,0x00,0x01]);
        this.keys = await this.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: "4096",
                publicExponent: EXPONENT,
                hash: { name:"SHA-256" }
            },
            true,
            ["encrypt","decrypt"]
        );
        return this;
    }
    async import(key,type="jwk"){
        if(type!=="jwk"){
            const n = type === "raw" ? C.x.byte_b64(key,"url") : key;
            key = {
                alg: "RSA-OAEP-256",
                e: "AQAB",
                ext: true,
                key_ops: ["encrypt"],
                kty: "RSA",
                n: n
            };
            type = "jwk";
        };
        const options = {
            name: "RSA-OAEP",
            hash: { name:"SHA-256" }
        };
        const ops = key.key_ops ||
            (type==="pkcs8" ? ["decrypt"] : ["encrypt"]);
        const d = await this.subtle.importKey(
            type, key, options, true, ops
        );
        if(d.type==="private") this.keys.privateKey = d;
        if(d.type==="public") this.keys.publicKey = d; 
        return this;
    }
    async export(type="jwk",priv){
        const t = type === "raw" ? (type="jwk",1) : 0;
        const key = priv ?
            this.keys.privateKey : this.keys.publicKey;
        const d = await this.subtle.exportKey(
            type, key
        );
        if(!priv&&t){
            return C.x.b64_byte(d.n,true);
        };
        return d;
    }
    async get_private_key(type){
        if(!this.keys.privateKey) await this.Error("get_private_key !this.keys.privateKey");
        const d = await this.export(type,true);
        return d;
    }
    async get_public_key(type){
        const d = await this.export(type);
        return d;
    }
    async encrypt(data){
        const d = await this.subtle.encrypt(
            {name:"RSA-OAEP"}, this.keys.publicKey, data
        );
        return d;
    }
    async decrypt(data){
        const d = await this.subtle.decrypt(
            {name:"RSA-OAEP"}, this.keys.privateKey, data
        );
        return d;
    }
    async aesEncrypt(body){
        const aes = await C.getAES();
        const obj = await aes.encrypt(body);
        const key = await aes.export("raw");
        obj.secret = await this.encrypt(key);
        return obj;
    }
    async aesDecrypt(data,iv,secret){
        const key = await this.decrypt(secret);
        const aes = await C.getAES(key);
        const d = await aes.decrypt(data,iv);
        return d;
    }
};



/**
 * @constructor
 * @classdesc 
 */
class ECDSAKey{
    constructor(){
        this.subtle = window.crypto.subtle;
        this.keys = {};
    }
    async Error(msg){
        throw new Error("ECDSAKey." + msg)
    }
    async init(key){
        if(!key) await this.generate();
        else await this.import(key);
        return this;
    }
    async generate(){
        this.keys = await this.subtle.generateKey(
            { name:"ECDSA", namedCurve:"P-256" },
            true,
            ["sign","verify"]
        );
        return this;
    }
    async import(key){
        const ops = key.key_ops || ["verify"];
        const d = await this.subtle.importKey(
            "jwk",
            key,
            {name:"ECDSA",namedCurve:"P-256"},
            true,
            ops
        );
        if(d.type==="private") this.keys.privateKey = d;
        if(d.type==="public") this.keys.publicKey = d;
        return this;
    }
    async export(type="jwk",priv){
        const key = priv ? this.keys.privateKey : this.keys.publicKey;
        const d = this.subtle.exportKey(
            "jwk",
            key
        );
        return d;
    }
    async get_private_key(type){
        if(!this.keys.privateKey) await this.Error("get_private_key !this.keys.privateKey");
        const d = await this.export(type,true);
        return d;
    }
    async get_public_key(type){
        const d = await this.export(type);
        return d;
    }
    async sign(data){
        const d = await this.subtle.sign(
            {name:"ECDSA", hash:{name:"SHA-256"}},
            this.keys.privateKey,
            data
        );
        return d;
    }
    async verify(data,sigunature){
        const r = await this.subtle.verify(
            {name:"ECDSA",hash:{name:"SHA-256"}},
            this.keys.publicKey,
            sigunature,
            data
        );
        return r;
    }
};



/**
 * 
 * @param {(ArrayBuffer|Uint8Array)} data
 * @returns {ArrayBuffer}
 */
async function SHA256(data){
    return await window.crypto.subtle.digest(
        { name: "SHA-256" },
        data.buffer || data
    )
};



/**
 * SHA-256
 * - String -> UTF8 -> SHA-256
 * @param {(String,ArrayBuffer,Uint8Array)} data
 * @param {String} encode - hex,base64,base64url,bs
 * @returns {(Uint8Array,String)}
 */
C.hash = async function(data,encode){
    if(typeof data==="string") data = C.UTF8.encode(data);
    const hash = await SHA256(data);
    return !encode ? hash : C.x.byte_x(hash,encode);
};

/**
 * AES-256-GCM
 * - encrypt
 * - decrypt
 * @param {(Object,String,Uint8Array,ArrayBuffer)} - key(jwk,base64url,Uint8Array,ArrayBuffer)
 * @returns {Object} - instance
 */
C.getAES = async function(key){
    const aes = new AESKey();
    await aes.init(key);
    return aes;
};

/**
 * RSA-4096-OAEP
 * - encrypt
 * - decrypt
 * - aesEncrypt
 * - aesDecrypt
 * @param {Object} - key(jwk)
 * @returns {Object} - instance
 */
C.getRSA = async function(key){
    const rsa = new RSAKey();
    await rsa.init(key);
    return rsa;
};

/**
 * ECDSA-256
 * - sign
 * - verify
 * @param {Object} - key(jwk)
 * @returns {Object} - instance
 */
C.getECDSA = async function(key){
    const ecdsa = new ECDSAKey();
    await ecdsa.init(key);
    return ecdsa;
};



Object.freeze(C);

export default C;


