import java.io.*;
import java.security.SecureRandom;

public class SM4Encrp {

    private static final int BLOCK = 16;//常量，表示16个byte

    private static final int KEYLENGTH = 128 / 8 / 4;//密钥长度，以字为单位

    private static final int[] FKS = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};//系统参数FK

    private static final int[] CK = {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

    private static final byte[][] sbox = {
            {(byte) 0xd6, (byte) 0x90, (byte) 0xe9, (byte) 0xfe, (byte) 0xcc, (byte) 0xe1, (byte) 0x3d, (byte) 0xb7, (byte) 0x16, (byte) 0xb6, (byte) 0x14, (byte) 0xc2, (byte) 0x28, (byte) 0xfb, (byte) 0x2c, (byte) 0x05},
            {(byte) 0x2b, (byte) 0x67, (byte) 0x9a, (byte) 0x76, (byte) 0x2a, (byte) 0xbe, (byte) 0x04, (byte) 0xc3, (byte) 0xaa, (byte) 0x44, (byte) 0x13, (byte) 0x26, (byte) 0x49, (byte) 0x86, (byte) 0x06, (byte) 0x99},
            {(byte) 0x9c, (byte) 0x42, (byte) 0x50, (byte) 0xf4, (byte) 0x91, (byte) 0xef, (byte) 0x98, (byte) 0x7a, (byte) 0x33, (byte) 0x54, (byte) 0x0b, (byte) 0x43, (byte) 0xed, (byte) 0xcf, (byte) 0xac, (byte) 0x62},
            {(byte) 0xe4, (byte) 0xb3, (byte) 0x1c, (byte) 0xa9, (byte) 0xc9, (byte) 0x08, (byte) 0xe8, (byte) 0x95, (byte) 0x80, (byte) 0xdf, (byte) 0x94, (byte) 0xfa, (byte) 0x75, (byte) 0x8f, (byte) 0x3f, (byte) 0xa6},
            {(byte) 0x47, (byte) 0x07, (byte) 0xa7, (byte) 0xfc, (byte) 0xf3, (byte) 0x73, (byte) 0x17, (byte) 0xba, (byte) 0x83, (byte) 0x59, (byte) 0x3c, (byte) 0x19, (byte) 0xe6, (byte) 0x85, (byte) 0x4f, (byte) 0xa8},
            {(byte) 0x68, (byte) 0x6b, (byte) 0x81, (byte) 0xb2, (byte) 0x71, (byte) 0x64, (byte) 0xda, (byte) 0x8b, (byte) 0xf8, (byte) 0xeb, (byte) 0x0f, (byte) 0x4b, (byte) 0x70, (byte) 0x56, (byte) 0x9d, (byte) 0x35},
            {(byte) 0x1e, (byte) 0x24, (byte) 0x0e, (byte) 0x5e, (byte) 0x63, (byte) 0x58, (byte) 0xd1, (byte) 0xa2, (byte) 0x25, (byte) 0x22, (byte) 0x7c, (byte) 0x3b, (byte) 0x01, (byte) 0x21, (byte) 0x78, (byte) 0x87},
            {(byte) 0xd4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9f, (byte) 0xd3, (byte) 0x27, (byte) 0x52, (byte) 0x4c, (byte) 0x36, (byte) 0x02, (byte) 0xe7, (byte) 0xa0, (byte) 0xc4, (byte) 0xc8, (byte) 0x9e},
            {(byte) 0xea, (byte) 0xbf, (byte) 0x8a, (byte) 0xd2, (byte) 0x40, (byte) 0xc7, (byte) 0x38, (byte) 0xb5, (byte) 0xa3, (byte) 0xf7, (byte) 0xf2, (byte) 0xce, (byte) 0xf9, (byte) 0x61, (byte) 0x15, (byte) 0xa1},
            {(byte) 0xe0, (byte) 0xae, (byte) 0x5d, (byte) 0xa4, (byte) 0x9b, (byte) 0x34, (byte) 0x1a, (byte) 0x55, (byte) 0xad, (byte) 0x93, (byte) 0x32, (byte) 0x30, (byte) 0xf5, (byte) 0x8c, (byte) 0xb1, (byte) 0xe3},
            {(byte) 0x1d, (byte) 0xf6, (byte) 0xe2, (byte) 0x2e, (byte) 0x82, (byte) 0x66, (byte) 0xca, (byte) 0x60, (byte) 0xc0, (byte) 0x29, (byte) 0x23, (byte) 0xab, (byte) 0x0d, (byte) 0x53, (byte) 0x4e, (byte) 0x6f},
            {(byte) 0xd5, (byte) 0xdb, (byte) 0x37, (byte) 0x45, (byte) 0xde, (byte) 0xfd, (byte) 0x8e, (byte) 0x2f, (byte) 0x03, (byte) 0xff, (byte) 0x6a, (byte) 0x72, (byte) 0x6d, (byte) 0x6c, (byte) 0x5b, (byte) 0x51},
            {(byte) 0x8d, (byte) 0x1b, (byte) 0xaf, (byte) 0x92, (byte) 0xbb, (byte) 0xdd, (byte) 0xbc, (byte) 0x7f, (byte) 0x11, (byte) 0xd9, (byte) 0x5c, (byte) 0x41, (byte) 0x1f, (byte) 0x10, (byte) 0x5a, (byte) 0xd8},
            {(byte) 0x0a, (byte) 0xc1, (byte) 0x31, (byte) 0x88, (byte) 0xa5, (byte) 0xcd, (byte) 0x7b, (byte) 0xbd, (byte) 0x2d, (byte) 0x74, (byte) 0xd0, (byte) 0x12, (byte) 0xb8, (byte) 0xe5, (byte) 0xb4, (byte) 0xb0},
            {(byte) 0x89, (byte) 0x69, (byte) 0x97, (byte) 0x4a, (byte) 0x0c, (byte) 0x96, (byte) 0x77, (byte) 0x7e, (byte) 0x65, (byte) 0xb9, (byte) 0xf1, (byte) 0x09, (byte) 0xc5, (byte) 0x6e, (byte) 0xc6, (byte) 0x84},
            {(byte) 0x18, (byte) 0xf0, (byte) 0x7d, (byte) 0xec, (byte) 0x3a, (byte) 0xdc, (byte) 0x4d, (byte) 0x20, (byte) 0x79, (byte) 0xee, (byte) 0x5f, (byte) 0x3e, (byte) 0xd7, (byte) 0xcb, (byte) 0x39, (byte) 0x48}
    };

    private int[] key;//原始密钥

    private int[] rks;//扩展密钥

    private String keyStr;//密钥字符串

    private byte[] bytes;//需要加密/解密的二进制

//    private byte[] bytesResult;//加密/解密后的二进制

    private SecureRandom random = new SecureRandom();//用来产生随机密钥

    private boolean isKeyInit = false;

    /**
     * 代码块，初始化
     */ {
        this.key = new int[KEYLENGTH];
        this.rks = new int[32];
    }

    /**
     * 内部生成密钥的构造方法
     *
     * @param bytes
     */
    public SM4Encrp(byte[] bytes) {
        this.bytes = bytes;
//        this.bytesResult = new byte[bytes.length];
        generateKey();
    }

    /**
     * 内部生成密钥的构造方法，支持文件输入流
     *
     * @param inputStream
     * @throws Exception
     */
    public SM4Encrp(InputStream inputStream) throws Exception {
        this.bytes = toBytes(inputStream);
//        this.bytesResult = new byte[this.bytes.length];
        generateKey();
    }

    public SM4Encrp(String keyStr, InputStream inputStream) throws Exception {
        this.bytes = toBytes(inputStream);
//        this.bytesResult = new byte[this.bytes.length];
        this.keyStr = keyStr;
        for (int i = 0; i < KEYLENGTH; i++) {
            this.key[i] = ((Long) Long.parseLong(keyStr.substring(8 * i, 8 * i + 8), 16)).intValue();
        }
    }

    /**
     * 可以指定加密密钥的构造方法
     *
     * @param keyStr
     * @param bytes
     */
    public SM4Encrp(String keyStr, byte[] bytes) throws Exception {
        if (keyStr.replaceAll(" |\t|-", "").length() != KEYLENGTH * 8) {
            System.out.println(keyStr);
            throw new Exception("指定的密钥长度非128比特位");
        }
        this.keyStr = keyStr;
        this.bytes = bytes;
//        this.bytesResult = new byte[bytes.length];
        for (int i = 0; i < KEYLENGTH; i++) {
            this.key[i] = ((Long) Long.parseLong(keyStr.substring(8 * i, 8 * i + 8), 16)).intValue();
        }
    }

    public SM4Encrp(String keyStr, String str) throws Exception {
        if (keyStr.replaceAll(" |\t|-", "").length() != KEYLENGTH * 8) {
            throw new Exception("指定的密钥长度非128比特位");
        }
        this.keyStr = keyStr;
        this.bytes = str.getBytes();

        for (int i = 0; i < KEYLENGTH; i++) {
            this.key[i] = ((Long) Long.parseLong(keyStr.substring(8 * i, 8 * i + 8), 16)).intValue();
        }
    }

    /**
     * 内部生成密钥的构造方法
     *
     * @param str
     */
    public SM4Encrp(String str) throws Exception {
        this.bytes = str.getBytes();
//        this.bytesResult = new byte[this.bytes.length];
        generateKey();
    }

    /**
     * 随机生成密钥
     */
    private void generateKey() {
        byte[] var2 = new byte[32];
        this.random.nextBytes(var2);
        for (int i = 0; i < KEYLENGTH; i++) {
            this.key[i] = byteArrayToInt(var2, 4 * i);
        }
        isKeyInit = true;
    }

    /**
     * 供外部获取内部生成的key
     *
     * @return
     */
    public String getKeyStr() {
        if (this.keyStr != null) {
            return this.keyStr;
        }
        if (this.isKeyInit) {
            this.keyStr = "";
            for (int i = 0; i < KEYLENGTH; i++) {
                if (Integer.toHexString(this.key[i]).length() < 8) {
                    for (int j = 0; j < 8 - Integer.toHexString(this.key[i]).length(); j++) {
                        this.keyStr += 0;
                    }
                }
                this.keyStr += Integer.toHexString(this.key[i]);
            }
            return this.keyStr;
        } else {
            generateKey();
            return getKeyStr();
        }
    }

    ////////////////////加密核心代码//////////////////////

    /**
     * 加密
     *
     * @return
     */
    public byte[] encrpt() {
        this.bytes = addBytes(new byte[16 - (this.bytes.length % 16 == 0 ? 16 : this.bytes.length % 16)]);
        keyExtend();//生成轮询密钥
        int nowPo = 0;//当前字开始位置
        for (int i = 0; i < this.bytes.length / BLOCK; i++, nowPo += BLOCK) {//分组
            int[] rows = new int[4 + 32];
            for (int j = 0; j < 4; j++) {
                rows[j] = byteArrayToInt(this.bytes, nowPo + j * 4);
            }
            for (int k = 0; k < 32; k++) {
                rows[k + 4] = rows[k] ^ TMethod(rows[k + 1] ^ rows[k + 2] ^ rows[k + 3] ^ this.rks[k]);
            }
            for (int k = 0; k < 4; k++) {
                System.arraycopy(intToByteArray(rows[35 - k]), 0, this.bytes, nowPo + 4 * k, 4);
            }
        }
        /*
         *将未分组byte移到结果
         */
        System.arraycopy(this.bytes, this.bytes.length / BLOCK * BLOCK, this.bytes, this.bytes.length / BLOCK * BLOCK, this.bytes.length % BLOCK);
        return this.bytes;
    }

    /**
     * 循环加密i次
     *
     * @param i
     * @return
     */
    public byte[] encrpt(int i) {
        for (int j = 0; j < i; j++) {
            this.bytes = encrpt();
        }
        return this.bytes;
    }

    /**
     * 解密，解密必须用外部指定解密密钥的方式进行
     *
     * @return
     */
    public byte[] decrpt() throws Exception {
        if (this.keyStr == null) {
            throw new Exception("未指定解密密钥！");
        }
        this.bytes = addBytes(new byte[16 - (this.bytes.length % 16 == 0 ? 16 : this.bytes.length % 16)]);
        keyExtend();//生成轮询密钥
        int nowPo = 0;//当前字开始位置
        for (int i = 0; i < this.bytes.length / BLOCK; i++, nowPo += BLOCK) {//分组
            int[] rows = new int[4 + 32];
            for (int j = 0; j < 4; j++) {
                rows[j] = byteArrayToInt(this.bytes, nowPo + j * 4);
            }
            for (int k = 0; k < 32; k++) {
                rows[k + 4] = rows[k] ^ TMethod(rows[k + 1] ^ rows[k + 2] ^ rows[k + 3] ^ this.rks[31 - k]);
            }
            for (int k = 0; k < 4; k++) {
                System.arraycopy(intToByteArray(rows[35 - k]), 0, this.bytes, nowPo + 4 * k, 4);
            }
        }
        /*
         *将未分组byte移到结果
         */
        System.arraycopy(this.bytes, this.bytes.length / BLOCK * BLOCK, this.bytes, this.bytes.length / BLOCK * BLOCK, this.bytes.length % BLOCK);
        return this.bytes;
    }

    /**
     * 解密i次加密后的数据
     *
     * @param i
     * @return
     */
    public byte[] decrpt(int i) throws Exception {
        for (int j = 0; j < i; j++) {
            this.bytes = decrpt();
        }
        return this.bytes;
    }

    /**
     * 密钥扩展算法
     */
    private void keyExtend() {
        int[] K = new int[36];
        int[] keys = {this.key[0] ^ this.FKS[0], this.key[1] ^ this.FKS[1], this.key[2] ^ this.FKS[2], this.key[3] ^ this.FKS[3]};
        System.arraycopy(keys, 0, K, 0, keys.length);
        for (int i = 0; i < 32; i++) {
            this.rks[i] = K[i] ^ TPMethod(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
            K[i + 4] = this.rks[i];
        }
    }

    /**
     * T方法原型
     *
     * @param a
     * @return
     */
    private int TMethod(int a) {
        byte[] as = intToByteArray(a);
        for (int i = 0; i < as.length; i++) {
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
    private int LMethod(int b) {
        return b ^ (circleLeftMove(b, 2)) ^ circleLeftMove(b, 10) ^ circleLeftMove(b, 18) ^ circleLeftMove(b, 24);
    }

    /**
     * 合成置换方法
     *
     * @param a
     * @return
     */
    private int TPMethod(int a) {
        byte[] as = intToByteArray(a);
        for (int i = 0; i < as.length; i++) {
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
    private int LPMethod(int b) {
        return b ^ (circleLeftMove(b, 13)) ^ circleLeftMove(b, 23);
    }

    /**
     * 实现在SBOX中查找相应的字节
     *
     * @param str
     * @return
     */
    private byte SBox(String str) {
        return SBox(Byte.parseByte(str, 16));
    }

    /**
     * 实现在SBOX中查找相应的字节
     *
     * @param b
     * @return
     */
    private byte SBox(byte b) {
        int lineNum = (b & 0xf0) >> 4;
        int columnNum = (b & 0x0f);
        return sbox[lineNum][columnNum];
    }

    ////////////////////加密支持方法//////////////////////

    /**
     * int正好为4字节，32比特，一个字
     * 本方法提供将byte转换为int的方法
     *
     * @param b
     * @param offset
     * @return
     */
    public static int byteArrayToInt(byte[] b, int offset) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
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
    private int circleLeftMove(int x, int leftL) {
        return (x << leftL) | (x >>> (32 - leftL));
    }

    /**
     * int转换为byte
     *
     * @param a
     * @return
     */
    public byte[] intToByteArray(int a) {
        return new byte[]{
                (byte) ((a >> 24) & 0xFF),
                (byte) ((a >> 16) & 0xFF),
                (byte) ((a >> 8) & 0xFF),
                (byte) (a & 0xFF)
        };
    }

    /**
     * 将输入流读取为byte数组
     *
     * @param inputStream
     * @return
     * @throws Exception
     */
    protected static byte[] toBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream swapStream = new ByteArrayOutputStream();
        byte[] buff = new byte[100]; //buff用于存放循环读取的临时数据
        int rc = 0;
        while ((rc = inputStream.read(buff, 0, 100)) > 0) {
            swapStream.write(buff, 0, rc);
        }
        byte[] in_b = swapStream.toByteArray(); //in_b为转换之后的结果 }
        return in_b;
    }

    /**
     * 将文件byte数组保存到指定的硬盘位置
     *
     * @param bytes
     * @param filePath
     * @throws Exception
     */
    public void storeFile(byte[] bytes, String filePath) throws Exception {
        File file = new File(filePath);
        OutputStream output = new FileOutputStream(file);
        BufferedOutputStream bufferedOutput = new BufferedOutputStream(output);
        bufferedOutput.write(bytes);
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

    public static void main(String[] args) {
        try {
//            SM4Encrp sm4Encrp = new SM4Encrp("0123456789abcdeffedcba9876543210 ", new byte[]{ 0x01,0x23,0x45, 0x67 ,(byte)0x89 ,(byte)0xab ,(byte)0xcd ,(byte)0xef ,(byte)0xfe ,(byte)0xdc ,(byte)0xba, (byte)0x98 ,0x76 ,0x54 ,0x32 ,0x10});
//            byte[] bytes = sm4Encrp.encrpt(1000000);
////            soutByte(bytes);
//            soutByte(bytes);
//            System.out.println();
//            byte[] b = new SM4Encrp(sm4Encrp.getKeyStr(), bytes).decrpt();
//            soutByte(new SM4Encrp(sm4Encrp.getKeyStr(), bytes).decrpt(1000000 ));

            long start = System.currentTimeMillis();
            SM4Encrp sm4Encrp1 = new SM4Encrp( "0123456789abcdeffedcba9876543210","中国人");
            byte[] bt = sm4Encrp1.encrpt();
            System.out.println(System.currentTimeMillis() - start);
            sm4Encrp1.storeFile(bt,"E:\\test1.pdf");

            SM4Encrp sm4Encrp2 = new SM4Encrp(sm4Encrp1.getKeyStr(),bt);
            byte[] e = sm4Encrp2.decrpt();
            System.out.println(new String(e));
//            System.out.println(new String(new SM4Encrp(sm4Encrp.getKeyStr(), bytes).decrpt()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void soutByte(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            System.out.print((bytes[i]) + " ");
        }
    }
}