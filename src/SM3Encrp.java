import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * 本类为国密SM3摘要算法的工具类
 */
public class SM3Encrp {

    private byte[] bytes;

    private byte[][] B;//原始分组

    private int[] Ws = new int[68];//W

    private int[] WPs = new int[64];//W'

    private static final int[] iV = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};//初始循环码

    private int[] result = new int[8];//每次存放的中间结果以及最后的结果

    {
        System.arraycopy(iV, 0, result, 0, result.length);//第一次初始化result为iv
    }

    public SM3Encrp(InputStream inputStream) throws IOException {
        this.bytes = SM4Encrp.toBytes(inputStream);
    }

    public SM3Encrp(byte[] bytes) {
        this.bytes = bytes;
    }

    public SM3Encrp(String string) {
        this.bytes = string.getBytes();
    }

    public int[] getEncrpResult() {
        fillBinDatas();//填充
        ExtendedPacket();//扩展
        IterationMethod();//迭代压缩
        for (int i = 0; i < 8; i++) {
            System.out.print(this.result[i] + " ");
        }
        System.out.println();
        return result;
    }

    public String getStringEncrpResult() {
        int[] rs = getEncrpResult();
        String string = "";
        for (int i = 0; i < rs.length; i++) {
            string += Integer.toHexString(rs[i]) + " ";
        }
        return string;
    }

    ////////////////////////////加密主体方法////////////////////////////////

    /**
     * 填充，将原先二进制填充为一个512比特倍数的byte数组
     *
     * @return
     */
    private void fillBinDatas() {
        byte[] lastByte = getLastByte();//构建源二进制长度的64比特表示
        this.bytes = addBytes(new byte[]{-128});//添加首位为1的一个字节
        if ((this.bytes.length + 8) % 64 != 0) {
            byte[] zeroBytes = ByteBuffer.allocate(64 - (this.bytes.length + 8) % 64).array();
            this.bytes = addBytes(zeroBytes);
            this.bytes = addBytes(lastByte);
        } else {
            this.bytes = addBytes(lastByte);
        }
    }

    /**
     * 消息扩展方法
     */
    private void ExtendedPacket() {
        /*
         *获取分组
         */
        this.B = new byte[this.bytes.length / 64][64];
        for (int i = 0; i < this.B.length; i++) {
            System.arraycopy(this.bytes, i * 64, this.B[i], 0, 64);
        }
    }


    /**
     * 迭代算法
     */
    private void IterationMethod() {
        for (int i = 0; i < this.B.length; i++) {
            getWnums(this.B[i]);//完善当前循环的W和W'
            this.result = CFMethod(this.result);
        }
    }

    /**
     * 压缩算法
     *
     * @param As
     * @return
     */
    private int[] CFMethod(int[] As) {
        int[] temp = new int[8];
        System.arraycopy(As, 0, temp, 0, temp.length);//上次运行结果拷贝
        try {
            for (int i = 0; i < 64; i++) {
                int ss1 = circleLeftMove(circleLeftMove(As[0], 12) + As[4] + circleLeftMove(getConst(i), i), 7);
                int ss2 = ss1 ^ circleLeftMove(As[0], 12);
                int tt1 = FbooleanMethod(As[0], As[1], As[2], i) + As[3] + ss2 + this.WPs[i];
                int tt2 = GbooleanMethod(As[4], As[5], As[6], i) + As[7] + ss1 + this.Ws[i];
                As[3] = As[2];
                As[2] = circleLeftMove(As[1], 9);
                As[1] = As[0];
                As[0] = tt1;
                As[7] = As[6];
                As[6] = circleLeftMove(As[5], 19);
                As[5] = As[4];
                As[4] = P0replacementMethod(tt2);
            }
            for (int i = 0; i < temp.length; i++) {
                As[i] = temp[i] ^ As[i];
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return As;
    }

    /**
     * 获取常量
     *
     * @param j
     * @return
     */
    private int getConst(int j) throws Exception {
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
    private int FbooleanMethod(int x, int y, int z, int j) throws Exception {
        if (j > 63)
            throw new Exception("j输入越界");
        if (j >= 0 && j <= 15)
            return x ^ y ^ z;
        else
            return (x | y) & (x | z) & (y | z);
    }

    /***
     * GG布尔函数
     * @param x
     * @param y
     * @param z
     * @param j
     * @return
     * @throws Exception
     */
    private int GbooleanMethod(int x, int y, int z, int j) throws Exception {
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
    private int P0replacementMethod(int x) {
        return x ^ (circleLeftMove(x, 9)) ^ (circleLeftMove(x, 17));
    }

    /**
     * P1置换函数
     *
     * @param x
     * @return
     */
    private int P1replacementMethod(int x) {
        return x ^ (circleLeftMove(x, 15)) ^ (circleLeftMove(x, 23));
    }

    /**
     * 完善当前的W和W'
     *
     * @param b
     */
    private void getWnums(byte[] b) {
        for (int i = 0; i < 64 / 4; i++) {
            this.Ws[i] = byteArrayToInt(b, 4 * i);
        }
        for (int i = 16; i < 68; i++) {
            this.Ws[i] = P1replacementMethod(this.Ws[i - 16] ^ this.Ws[i - 9] ^ circleLeftMove(this.Ws[i - 3], 15)) ^ circleLeftMove(this.Ws[i - 13], 7) ^ this.Ws[i - 6];
        }
        for (int i = 0; i < 64; i++) {
            this.WPs[i] = this.Ws[i] ^ this.Ws[i + 4];
        }
    }
    ////////////////////////////加密支持方法///////////////////////////////

    /**
     * 循环左移
     *
     * @param x
     * @param leftL
     * @return
     */
    private int circleLeftMove(int x, int leftL) {
        return (x << leftL) | (x >>> (32 - leftL));
    }

    /**
     * 在本类中bytes后添加bytes
     *
     * @param bytes
     * @return
     */
    private byte[] addBytes(byte[] bytes) {
        byte[] bt = new byte[this.bytes.length + bytes.length];
        System.arraycopy(this.bytes, 0, bt, 0, this.bytes.length);
        System.arraycopy(bytes, 0, bt, this.bytes.length, bytes.length);
        return bt;
    }

    /**
     * 获取原始bytes长度表示为64比特作为填充的最后
     *
     * @return
     */
    private byte[] getLastByte() {
        long length = this.bytes.length * 8;
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(0, length);
        return buffer.array();
    }

    /**
     * int正好为4字节，32比特，一个字
     * 本方法提供将byte转换为int的方法
     *
     * @param b
     * @param offset
     * @return
     */
    public int byteArrayToInt(byte[] b, int offset) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }

    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        try {
            SM3Encrp s = new SM3Encrp(new byte[]{0x61,0x62,0x63,(byte)0xff});
            System.out.println(s.getStringEncrpResult());
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(System.currentTimeMillis() - start);
    }
}