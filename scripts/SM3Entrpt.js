var iV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];// 初始循环码

var SM3Entrpt = function(bytes)
{
    var me = this;

    me.bytes = bytes;

    me.B = new Array();

    me.Ws = new Int32Array(68);

    me.WPs = new Int32Array(64);

    me.result = new Int32Array(8);

    me.init = function()
    {
        copyArray(iV, 0, me.result, 0, iV.length);
    }

    me.getEncrpResult = function()
    {
        me.init();
        fillBinDatas();// 填充
        ExtendedPacket();// 扩展
        IterationMethod();// 迭代压缩
        return me.result;
    }

    me.getStringEncrpResult = function()
    {
        var rs = me.getEncrpResult();
        var string = "";
        var res = new Uint32Array(me.result.length);
        copyArray(rs, 0, res, 0, rs.length);
        for (var i = 0; i < rs.length; i++)
        {
            string += res[i].toString(16) + " ";
        }
        return string;
    }

    // //////////////////////////加密主体方法////////////////////////////////

    /**
     * 填充，将原先二进制填充为一个512比特倍数的byte数组
     * 
     * @return
     */
    function fillBinDatas()
    {
        var lastByte = getLastByte();// 构建源二进制长度的64比特表示
        addBytes([0x80]);// 添加首位为1的一个字节
        var len = me.bytes.length;
        if ((me.bytes.length + 8) % 64 != 0)
        {
            var zeroBytes = new Array();
            for (var i = 0; i < (64 - (len + 8) % 64); i++)
            {
                zeroBytes.push(0x00);
            }
            addBytes(zeroBytes);
            addBytes(lastByte);
        } else
        {
            addBytes(lastByte);
        }
    }

    /**
     * 消息扩展方法
     */
    function ExtendedPacket()
    {
        /*
         * 获取分组
         */
        me.B = new Array();
        for (var i = 0; i < me.bytes.length / 64; i++)
        {
            me.B[i] = new Array();
            copyArray(me.bytes, i * 64, me.B[i], 0, 64);
        }
    }

    /**
     * 迭代算法
     */
    function IterationMethod()
    {
        for (var i = 0; i < me.B.length; i++)
        {
            getWnums(me.B[i]);// 完善当前循环的W和W'
            me.result = CFMethod(me.result);
        }
    }

    /**
     * 压缩算法
     * 
     * @param As
     * @return
     */
    function CFMethod(As)
    {
        var temp = new Array();
        copyArray(As, 0, temp, 0, As.length);// 上次运行结果拷贝
        for (var i = 0; i < 64; i++)
        {
            var ss1 = circleLeftMove(circleLeftMove(As[0], 12) + As[4] + circleLeftMove(getConst(i), i), 7);
            var ss2 = ss1 ^ circleLeftMove(As[0], 12);
            var tt1 = FbooleanMethod(As[0], As[1], As[2], i) + As[3] + ss2 + me.WPs[i];
            var tt2 = GbooleanMethod(As[4], As[5], As[6], i) + As[7] + ss1 + me.Ws[i];
            As[3] = As[2];
            As[2] = circleLeftMove(As[1], 9);
            As[1] = As[0];
            As[0] = tt1;
            As[7] = As[6];
            As[6] = circleLeftMove(As[5], 19);
            As[5] = As[4];
            As[4] = P0replacementMethod(tt2);
        }
        for (var i = 0; i < temp.length; i++)
        {
            As[i] = temp[i] ^ As[i];
        }
        return As;
    }

    /**
     * 获取常量
     * 
     * @param j
     * @return
     */
    function getConst(j)
    {
        if (j > 64)
            throw new Exception("j数值越界");
        if (j >= 0 && j <= 15)
            return 0x79cc4519;
        else
            return 0x7a879d8a;
    }

    /**
     * FF布尔函数
     * 
     * @param x
     * @param y
     * @param z
     * @param j
     * @return
     */
    function FbooleanMethod(x, y, z, j)
    {
        if (j > 63)
            throw new Exception("j输入越界");
        if (j >= 0 && j <= 15)
            return x ^ y ^ z;
        else
            return (x | y) & (x | z) & (y | z);
    }

    /***************************************************************************
     * GG布尔函数
     * 
     * @param x
     * @param y
     * @param z
     * @param j
     * @return
     * @throws Exception
     */
    function GbooleanMethod(x, y, z, j)
    {
        if (j > 63)
            throw new Exception("j输入越界");
        if (j >= 0 && j <= 15)
            return x ^ y ^ z;
        else
            return (x & y) | (~x & z);
    }

    /**
     * P0置换函数
     * 
     * @param x
     * @return
     */
    function P0replacementMethod(x)
    {
        return x ^ (circleLeftMove(x, 9)) ^ (circleLeftMove(x, 17));
    }

    /**
     * P1置换函数
     * 
     * @param x
     * @return
     */
    function P1replacementMethod(x)
    {
        return x ^ (circleLeftMove(x, 15)) ^ (circleLeftMove(x, 23));
    }

    /**
     * 完善当前的W和W'
     * 
     * @param b
     */
    function getWnums(b)
    {
        for (var i = 0; i < 64 / 4; i++)
        {
            me.Ws[i] = byteArrayToInt(b, 4 * i);
        }
        for (var i = 16; i < 68; i++)
        {
            me.Ws[i] = P1replacementMethod(me.Ws[i - 16] ^ me.Ws[i - 9] ^ circleLeftMove(me.Ws[i - 3], 15))
            ^ circleLeftMove(me.Ws[i - 13], 7) ^ me.Ws[i - 6];
        }
        for (var i = 0; i < 64; i++)
        {
            me.WPs[i] = me.Ws[i] ^ me.Ws[i + 4];
        }
    }
    // //////////////////////////加密支持方法///////////////////////////////

    /**
     * 循环左移
     * 
     * @param x
     * @param leftL
     * @return
     */
    function circleLeftMove(x, leftL)
    {
        return (x << leftL) | (x >>> (32 - leftL));
    }

    /**
     * 在本类中bytes后添加bytes
     * 
     * @param bytes
     * @return
     */
    function addBytes(bytes)
    {
        copyArray(bytes, 0, me.bytes, me.bytes.length, bytes.length);
    }

    /**
     * 获取原始bytes长度表示为64比特作为填充的最后
     * 
     * @return
     */
    function getLastByte()
    {
        var length = me.bytes.length * 8;
        var lenStr = me.getBinStr(length);
        var result = new Array();
        for (var i = 0; i < 64 / 8; i++)
        {
            result.push(parseInt(lenStr.substr(8 * i, 8), 2));
        }
        return result;
    }

    me.getBinStr = function(num)
    {
        var str = "";
        while (num > 1)
        {
            str = num % 2 + str;
            num = num % 2 == 0 ? num / 2 : (num - 1) / 2;
        }
        str = 1 + str;
        var len = 64 - str.length;
        for (var i = 0; i < len; i++)
        {
            str = "0" + str;
        }
        return str;
    }

    /**
     * int正好为4字节，32比特，一个字 本方法提供将byte转换为int的方法
     * 
     * @param b
     * @param offset
     * @return
     */
    function byteArrayToInt(b, offset)
    {
        var value = 0;
        for (var i = 0; i < 4; i++)
        {
            var shift = (4 - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }

    /**
     * 数组复制函数
     * 
     * @param fromDt
     * @param toDt
     * @param len
     */
    function copyArray(fromDt, from, toDt, atNum, len)
    {
        if (typeof(atNum) != "number" || typeof(len) != "number")
        {
            throw new Error("数组复制方法参数异常");
        }
        for (var i = atNum; i < atNum + len; i++)
        {
            toDt[i] = fromDt[i - atNum + from];
        }
    }
}

var sm = new SM3Entrpt([0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64]);
// console.log(sm.getEncrpResult())
console.log(sm.getStringEncrpResult())