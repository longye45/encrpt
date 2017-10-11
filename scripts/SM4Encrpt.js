/**
 * 本JavaScript为国密sm4加密/解密的JavaScript实现 ，本类的核心方法为encrpt与decrpt，分别对应加密与解密。本类的具体使用方式如下
 * var test = new SM4Encrpt({   //实例化解密类
 *      （key/keyStr）:***,//指定的数组加密/解密密钥数组/密钥字符串，此参数若是加密可以省略，加密密钥由本类自动生成；若是解密必须指定该密钥
 *      bytes/enStr:*** //需要加密/解密的二进制/字符串
 * });
 * test.encrpt();//此为加密方法
 * test.encrpt(100);//此为加密100次
 * test.decrpt();//此为解密方法
 * test.decrpt(100);此为解密100次
 * 以上为标准的加密解密过程
 * 
 * 其他可供外部调用的方法如下：
 * test.getResultStr();//获取加密/解密后的字符串
 * test.getkeyStr();//获取当前加密或者解密的密钥字符串
 */
var SM4Encrpt = function () {

    var BLOCK = 16;

    var KEYLENGTH = 128 / 8 / 4; // 密钥长度，以字为单位

    var FKS = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]; // 系统参数FK

    var CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279];

    var sbox = [
        [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05],
        [0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
        [0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62],
        [0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6],
        [0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8],
        [0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35],
        [0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87],
        [0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e],
        [0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1],
        [0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3],
        [0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f],
        [0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51],
        [0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8],
        [0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0],
        [0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84],
        [0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]
    ];

    var me = this;

    me.key = new Uint32Array(KEYLENGTH); //数组形式的加密密钥

    me.rks = new Uint32Array(32); //轮询密钥

    me.bytes = null; //加密/解密的bytes

    me.keyStr = ''; // 密钥字符串,真正使用的是key

    me.isKeyInit = false; //密钥是否初始化完成

    me.enstr = ''; //需要加密的字符串

    /**
     * 初始化方法
     * @param {*} options 
     */
    function _init(options) {
        for (var key in options) {
            if (options.hasOwnProperty(key)) {
                me[key] = options[key];
            }
        }
        if (me.bytes == null && me.enstr == '') {
            throw Error('请指定加/解密的比特数组');
        }

        if (me.enstr != '') {
            me.bytes = stringToByte(me.enstr);
        }

        if (me.keyStr == '') {
            generateKey(); //如果初始化未发现字符串密钥则生成密钥
            return;
        }

        if (me.keyStr.length != 32) {
            throw Error('密钥长度为32位十六进制字符串');
        }

        getKeyFromStr();

    }

    function getKeyFromStr() {
        for (var i = 0; i < me.key.length; i++) {
            me.key[i] = parseInt(me.keyStr.substr(8 * i, 8), 16);
        }
    }

    /**
     * 随机生成密钥
     */
    function generateKey() {
        for (var i = 0; i < KEYLENGTH; i++) {
            var var2 = getRadomBytes();
            me.key[i] = byteArrayToInt(var2.bytes, 0);
            me.keyStr += var2.bytesstr;
        }
        me.isKeyInit = true;
    }

    function getRadomBytes() {
        var numtostr = '0123456789abcdef';
        var result = {
            bytes: [0, 0, 0, 0],
            bytesstr: ''
        };
        for (var j = 0; j < 4; j++) {
            for (var i = 1; i >= 0; i--) {
                var num = (Math.random() * 15).toFixed(0);
                result.bytes[j] += num << (4 * i);
                result.bytesstr += numtostr.charAt(num);
            }
        }
        return result;
    }

    /**
     * 供外部获取内部生成的key
     * 
     * @return
     */
    me.getKeyStr = function () {
        if (me.keyStr != null || me.keyStr != '') {
            return me.keyStr;
        }
        generateKey();
        return getKeyStr();
    }

    // //////////////////加密核心代码//////////////////////

    /**
     * 加密
     * 
     * @return
     */
    me.encrpt = function () {
        var times = arguments.length == 0 ? 1 : arguments[0]; //加密次数
        if (checkArguments(arguments)) {
            if (times == 0) {
                return me.bytes;
            } else {
                keyExtend(); // 生成轮询密钥
                var nowPo = 0; // 当前字开始位置
                for (var i = 0; i < me.bytes.length / BLOCK; i++, nowPo += BLOCK) { // 分组
                    var rows = new Uint32Array(4 + 32);
                    for (var j = 0; j < 4; j++) {
                        rows[j] = byteArrayToInt(me.bytes, nowPo + j * 4);
                    }
                    for (var k = 0; k < 32; k++) {
                        rows[k + 4] = rows[k] ^ TMethod(rows[k + 1] ^ rows[k + 2] ^ rows[k + 3] ^ me.rks[k]);
                    }
                    for (var k = 0; k < 4; k++) {
                        copyArray(intToByteArray(rows[35 - k]), 0, me.bytes, nowPo + 4 * k, 4);
                    }
                }
                return me.encrpt(--times);
            }
        }
    }

    /**
     * 解密，解密必须用外部指定解密密钥的方式进行
     * 
     * @return
     */
    me.decrpt = function () {
        if (me.keyStr == null || me.keyStr == '') {
            throw Error("未指定解密密钥！");
        }
        var times = arguments.length == 0 ? 1 : arguments[0]; //加密次数
        if (checkArguments(arguments)) {
            if (times == 0) {
                return me.bytes;
            } else {
                keyExtend(); // 生成轮询密钥
                var nowPo = 0; // 当前字开始位置
                for (var i = 0; i < me.bytes.length / BLOCK; i++, nowPo += BLOCK) { // 分组
                    var rows = new Uint32Array(4 + 32);
                    for (var j = 0; j < 4; j++) {
                        rows[j] = byteArrayToInt(me.bytes, nowPo + j * 4);
                    }
                    for (var k = 0; k < 32; k++) {
                        rows[k + 4] = rows[k] ^ TMethod(rows[k + 1] ^ rows[k + 2] ^ rows[k + 3] ^ me.rks[31 - k]);
                    }
                    for (var k = 0; k < 4; k++) {
                        copyArray(intToByteArray(rows[35 - k]), 0, me.bytes, nowPo + 4 * k, 4);
                    }
                }
                return me.decrpt(--times);
            }
        }
    }

    /**
     * 获取加密后或解密后的字符串
     */
    me.getResultStr = function () {
        return byteToString(me.bytes);
    }

    /**
     * 密钥扩展算法
     */
    function keyExtend() {
        var K = new Uint32Array(36);
        var keys = [
            me.key[0] ^ FKS[0],
            me.key[1] ^ FKS[1],
            me.key[2] ^ FKS[2],
            me.key[3] ^ FKS[3]
        ];
        copyArray(keys, 0, K, 0, keys.length);
        for (var i = 0; i < 32; i++) {
            me.rks[i] = K[i] ^ TPMethod(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
            K[i + 4] = me.rks[i];
        }
    }

    /**
     * T方法原型
     * 
     * @param a
     * @return
     */
    function TMethod(a) {
        var as = intToByteArray(a);
        for (var i = 0; i < as.length; i++) {
            as[i] = SBox(as[i]);
        }
        return LMethod(byteArrayToInt(as, 0));
    }

    /**
     * 原型L方法
     * 
     * @param b
     * @return
     */
    function LMethod(b) {
        return b ^ (circleLeftMove(b, 2)) ^ circleLeftMove(b, 10) ^ circleLeftMove(b, 18) ^ circleLeftMove(b, 24);
    }

    /**
     * 合成置换方法
     * 
     * @param a
     * @return
     */
    function TPMethod(a) {
        var as = intToByteArray(a);
        for (var i = 0; i < as.length; i++) {
            as[i] = SBox(as[i]);
        }
        return LPMethod(byteArrayToInt(as, 0));
    }

    /**
     * 线性变换函数(修改后)
     * 
     * @param b
     * @return
     */
    function LPMethod(b) {
        return b ^ (circleLeftMove(b, 13)) ^ circleLeftMove(b, 23);
    }

    /**
     * 实现在SBOX中查找相应的字节
     * 
     * @param str
     * @return
     */
    function SBox(str) {
        return SBox(Byte.parseByte(str, 16));
    }

    /**
     * 实现在SBOX中查找相应的字节
     * 
     * @param b
     * @return
     */
    function SBox(b) {
        var lineNum = (b & 0xf0) >> 4;
        var columnNum = (b & 0x0f);
        return sbox[lineNum][columnNum];
    }

    // //////////////////加密支持方法//////////////////////

    /**
     * int正好为4字节，32比特，一个字 本方法提供将byte转换为int的方法
     * 
     * @param b
     * @param offsetP
     * @return
     */
    function byteArrayToInt(b, offset) {
        var value = 0;
        for (var i = 0; i < 4; i++) {
            var shift = (4 - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }

    /**
     * 循环左移
     * 
     * @param x
     * @param leftL
     * @return
     */
    function circleLeftMove(x, leftL) {
        return (x << leftL) | (x >>> (32 - leftL));
    }

    /**
     * int转换为byte
     * 
     * @param a
     * @return
     */
    function intToByteArray(a) {
        return [((a >> 24) & 0xFF), ((a >> 16) & 0xFF), ((a >> 8) & 0xFF), (a & 0xFF)];
    }

    /**
     * 数组复制函数
     * 
     * @param fromDt
     * @param toDt
     * @param len
     */
    function copyArray(fromDt, from, toDt, atNum, len) {
        if (typeof (atNum) != "number" || typeof (len) != "number") {
            throw new Error("数组复制方法参数异常");
        }
        for (var i = atNum; i < atNum + len; i++) {
            toDt[i] = fromDt[i - atNum + from];
        }
    }

    /**
     * 判断输入参数是否合法
     * @param {*参数} args 
     */
    function checkArguments(args) {
        if (args.length > 2 || (args.length == 1 && typeof (args[0]) != "number"))
            throw Error("加/解密次数输入异常");
        return true;
    }

    /**
     * 字符串转byte数组
     * @param {*字符串} str 
     */
    function stringToByte(str) {
        var bytes = new Array();
        var len, c;
        len = str.length;
        for (var i = 0; i < len; i++) {
            c = str.charCodeAt(i);
            if (c >= 0x010000 && c <= 0x10FFFF) {
                bytes.push(((c >> 18) & 0x07) | 0xF0);
                bytes.push(((c >> 12) & 0x3F) | 0x80);
                bytes.push(((c >> 6) & 0x3F) | 0x80);
                bytes.push((c & 0x3F) | 0x80);
            } else if (c >= 0x000800 && c <= 0x00FFFF) {
                bytes.push(((c >> 12) & 0x0F) | 0xE0);
                bytes.push(((c >> 6) & 0x3F) | 0x80);
                bytes.push((c & 0x3F) | 0x80);
            } else if (c >= 0x000080 && c <= 0x0007FF) {
                bytes.push(((c >> 6) & 0x1F) | 0xC0);
                bytes.push((c & 0x3F) | 0x80);
            } else {
                bytes.push(c & 0xFF);
            }
        }
        return bytes;
    }

    /**
     * byte数组转字符串
     * @param {*byte数组} arr 
     */
    function byteToString(arr) {
        if (typeof arr === 'string') {
            return arr;
        }
        var str = '',
            _arr = arr;
        for (var i = 0; i < _arr.length; i++) {
            var one = _arr[i].toString(2),
                v = one.match(/^1+?(?=0)/);
            if (v && one.length == 8) {
                var bytesLength = v[0].length;
                var store = _arr[i].toString(2).slice(7 - bytesLength);
                for (var st = 1; st < bytesLength; st++) {
                    store += _arr[st + i].toString(2).slice(2);
                }
                str += String.fromCharCode(parseInt(store, 2));
                i += bytesLength - 1;
            } else {
                str += String.fromCharCode(_arr[i]);
            }
        }
        return str;
    }

    _init(arguments[0]);
}