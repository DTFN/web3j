/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.sql.SQLSyntaxErrorException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutionException;

import com.fasterxml.jackson.databind.ObjectMapper;
import jnr.a64asm.SYSREG_CODE;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.Test;

import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.BaseEventResponse;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Bytes;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import org.web3j.crypto.gm.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.web3j.rlp.RlpDecoder.OFFSET_SHORT_STRING;

public class WalletTest {

    private static String cre_json_big_guy = "{\"address\":\"b3d49259b486d04505b0b652ade74849c0b703c3\",\"crypto\":{\"cipher\":\"aes-128-ctr\"," +
            "\"ciphertext\":\"51de3bf928a54245280810f91f4992a8f08178356c0bbfd9b7a124311e7ef7f9\",\"cipherparams\":{\"iv\":\"" +
            "3b119ac1c4159855227dbbcec7145ced\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"" +
            "9614516f90c2bbb5ca08a9aa81924ec538dd834c3572ee2812f889716512a57f\"},\"mac\":\"473aa86b74de993d14d85aacb2d8fc14a4a47032fe44e0991d981d2810cc4205\"}," +
            "\"id\":\"f95c41fe-d1f7-4f56-bf96-0523778ccada\",\"version\":3}";

    public static String cre_json_normal_account = "{\"address\":\"796e349a1252b43e358aa65e4c19a52e1375f9eb\"," +
            "\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"a7c26e503dbc18efbbea37f50686497794b0db0fac256bea71cec9f9b833a1d4\"," +
            "\"cipherparams\":{\"iv\":\"53c6dd793fe65d2498a5eb03bd786be9\"},\"kdf\":\"scrypt\",\"kdfparams\"" +
            ":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"8ac577382898b191001c98bad97a6cfc634b20f4a8aeed52c1319d75e81311dd\"},\"mac\":" +
            "\"5edce2d86165189c55d5b74e696ff4a10841ec16f4ad248fa1b185282b488e66\"},\"id\":\"f2b04fd3-db4a-4891-9aa5-0e613509fb6b\",\"version\":3}";

    public static Credentials loadColdWalletNormalAccount() throws CipherException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        String json = cre_json_normal_account;
        WalletFile walletFile = objectMapper.readValue(json, WalletFile.class);
        Credentials coldwallet = Credentials.create(Wallet.decrypt("123", walletFile));
        return coldwallet;
    }

    public static Credentials loadColdWalletBigGuy() throws CipherException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        String json = cre_json_big_guy;
        WalletFile walletFile = objectMapper.readValue(json, WalletFile.class);
        Credentials coldwallet = Credentials.create(Wallet.decrypt("123", walletFile));
        return coldwallet;
    }

    private static byte[] gm_encode(RawTransactionWithKey rawTransaction, SM2.Signature signatureData) {
        List<RlpType> values = gm_asRlpValues(rawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    public static List<RlpType> gm_asRlpValues(
            RawTransactionWithKey rawTransaction, SM2.Signature signatureData) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(rawTransaction.getNonce()));
        result.add(RlpString.create(rawTransaction.getGasPrice()));
        result.add(RlpString.create(rawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = rawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(rawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(rawTransaction.getData());
        result.add(RlpString.create(data));

        // add gas premium and fee cap if this is an EIP-1559 transaction
        if (rawTransaction.isEIP1559Transaction()) {
            result.add(RlpString.create(rawTransaction.getGasPremium()));
            result.add(RlpString.create(rawTransaction.getFeeCap()));
        }

        if (signatureData != null) {
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.GetV().toByteArray())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.GetR().toByteArray())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.GetS().toByteArray())));
            // 将公钥放在交易数据中
            result.add(RlpString.create(Bytes.trimLeadingZeroes(rawTransaction.getPublicKeyX().toByteArray())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(rawTransaction.getPublicKeyY().toByteArray())));
        }

        return result;
    }

    private static int printArray(String source, byte[] array) {
        System.out.print(source);
        System.out.print(": ");
        for (int i=0; i< array.length; i++) {
            int item = array[i] & 0xff;
            System.out.print(item);
            System.out.print(" ");
        }
        System.out.println("");

        return 0;
    }

    @Test
    public void testGuomi() throws  Exception {
        String ppchainprivateadmin = "0x121f5ef0aba86e258bfd9d6063b52774c1598adf";
        float value = 123456;

        //Credentials credentials = loadColdWalletBigGuy();
        Credentials credentials = loadColdWalletNormalAccount();

        BigInteger GAS_PRICE = BigInteger.valueOf(22000000000L);
        BigInteger GAS_LIMIT = BigInteger.valueOf(4_300_000);

        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8545"));

        String ownAddress = credentials.getAddress();

        EthGetTransactionCount ethGetTransactionCount = null;
        try {
            ethGetTransactionCount = web3j.ethGetTransactionCount(
                    ownAddress, DefaultBlockParameterName.PENDING).sendAsync().get();
        } catch (InterruptedException e) {
            System.out.println("获取nonce错误 111");
            System.out.println(e.getMessage());
        } catch (ExecutionException e) {
            System.out.println("获取nonce错误 222");
            System.out.println(e.getMessage());
        }
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();

        byte[] default_id = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
        String IDA = new String(default_id);

        SM2 sm2 = new SM2();

        System.out.print("发送账户地址：");
        System.out.println(credentials.getAddress());

        SM2KeyPair sm2KeyPair = sm2.generateKeyPairFromKey(credentials.getEcKeyPair().getPrivateKey());

        /*
            System.out.print("私钥：");
            System.out.println(sm2KeyPair.getPrivateKey());
            System.out.print("公钥-X: ");
            System.out.println(sm2KeyPair.getPublicKey().getXCoord().toBigInteger());
            System.out.print("公钥-Y: ");
            System.out.println(sm2KeyPair.getPublicKey().getYCoord().toBigInteger());
         */

        BigInteger ethValue = Convert.toWei(String.valueOf(value), Convert.Unit.ETHER).toBigInteger();
        RawTransactionWithKey rawTransaction = RawTransactionWithKey.createTransaction(
                nonce, GAS_PRICE, GAS_LIMIT, ppchainprivateadmin, ethValue, "",
                sm2KeyPair.getPublicKey().getXCoord().toBigInteger(),
                sm2KeyPair.getPublicKey().getYCoord().toBigInteger());

        byte[] encodedTransaction = gm_encode(rawTransaction, null);

        String base64EncodedTransaction = Base64.getEncoder().encodeToString(encodedTransaction);

        SM2.Signature signature = sm2.sign(base64EncodedTransaction, IDA, sm2KeyPair);

        byte[] finalEncodedTransaction = gm_encode(rawTransaction, signature);

        String hexValue = Numeric.toHexString(finalEncodedTransaction);

        // 发送交易
        EthSendTransaction ethSendTransaction = null;
        try {
            ethSendTransaction = web3j.ethSendRawTransaction(hexValue).sendAsync().get();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        String transactionHash = ethSendTransaction.getTransactionHash();
        if (ethSendTransaction.hasError()) {
            System.out.print("发送交易错误: ");
            System.out.println(ethSendTransaction.getError().getMessage());
        }

        System.out.printf("发送交易成功，交易HASH: %s\n", transactionHash);
    }

    @Test
    public void testCreateStandard() throws Exception {
        testCreate(Wallet.createStandard(SampleKeys.PASSWORD, SampleKeys.KEY_PAIR));
    }

    @Test
    public void testCreateLight() throws Exception {
        testCreate(Wallet.createLight(SampleKeys.PASSWORD, SampleKeys.KEY_PAIR));
    }

    private void testCreate(WalletFile walletFile) throws Exception {
        assertEquals(walletFile.getAddress(), (SampleKeys.ADDRESS_NO_PREFIX));
    }

    @Test
    public void testEncryptDecryptStandard() throws Exception {
        testEncryptDecrypt(Wallet.createStandard(SampleKeys.PASSWORD, SampleKeys.KEY_PAIR));
    }

    @Test
    public void testEncryptDecryptLight() throws Exception {
        testEncryptDecrypt(Wallet.createLight(SampleKeys.PASSWORD, SampleKeys.KEY_PAIR));
    }

    private void testEncryptDecrypt(WalletFile walletFile) throws Exception {
        assertEquals(Wallet.decrypt(SampleKeys.PASSWORD, walletFile), (SampleKeys.KEY_PAIR));
    }

    @Test
    public void testDecryptAes128Ctr() throws Exception {
        WalletFile walletFile = load(AES_128_CTR);
        ECKeyPair ecKeyPair = Wallet.decrypt(PASSWORD, walletFile);
        assertEquals(Numeric.toHexStringNoPrefix(ecKeyPair.getPrivateKey()), (SECRET));
    }

    @Test
    public void testDecryptScrypt() throws Exception {
        WalletFile walletFile = load(SCRYPT);
        ECKeyPair ecKeyPair = Wallet.decrypt(PASSWORD, walletFile);
        assertEquals(Numeric.toHexStringNoPrefix(ecKeyPair.getPrivateKey()), (SECRET));
    }

    @Test
    public void testGenerateRandomBytes() {
        assertArrayEquals(Wallet.generateRandomBytes(0), (new byte[] {}));
        assertEquals(Wallet.generateRandomBytes(10).length, (10));
    }

    private WalletFile load(String source) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(source, WalletFile.class);
    }

    private static final String PASSWORD = "Insecure Pa55w0rd";
    private static final String SECRET =
            "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6";

    private static final String AES_128_CTR =
            "{\n"
                    + "    \"crypto\" : {\n"
                    + "        \"cipher\" : \"aes-128-ctr\",\n"
                    + "        \"cipherparams\" : {\n"
                    + "            \"iv\" : \"02ebc768684e5576900376114625ee6f\"\n"
                    + "        },\n"
                    + "        \"ciphertext\" : \"7ad5c9dd2c95f34a92ebb86740b92103a5d1cc4c2eabf3b9a59e1f83f3181216\",\n"
                    + "        \"kdf\" : \"pbkdf2\",\n"
                    + "        \"kdfparams\" : {\n"
                    + "            \"c\" : 262144,\n"
                    + "            \"dklen\" : 32,\n"
                    + "            \"prf\" : \"hmac-sha256\",\n"
                    + "            \"salt\" : \"0e4cf3893b25bb81efaae565728b5b7cde6a84e224cbf9aed3d69a31c981b702\"\n"
                    + "        },\n"
                    + "        \"mac\" : \"2b29e4641ec17f4dc8b86fc8592090b50109b372529c30b001d4d96249edaf62\"\n"
                    + "    },\n"
                    + "    \"id\" : \"af0451b4-6020-4ef0-91ec-794a5a965b01\",\n"
                    + "    \"version\" : 3\n"
                    + "}";

    private static final String SCRYPT =
            "{\n"
                    + "    \"crypto\" : {\n"
                    + "        \"cipher\" : \"aes-128-ctr\",\n"
                    + "        \"cipherparams\" : {\n"
                    + "            \"iv\" : \"3021e1ef4774dfc5b08307f3a4c8df00\"\n"
                    + "        },\n"
                    + "        \"ciphertext\" : \"4dd29ba18478b98cf07a8a44167acdf7e04de59777c4b9c139e3d3fa5cb0b931\",\n"
                    + "        \"kdf\" : \"scrypt\",\n"
                    + "        \"kdfparams\" : {\n"
                    + "            \"dklen\" : 32,\n"
                    + "            \"n\" : 262144,\n"
                    + "            \"r\" : 8,\n"
                    + "            \"p\" : 1,\n"
                    + "            \"salt\" : \"4f9f68c71989eb3887cd947c80b9555fce528f210199d35c35279beb8c2da5ca\"\n"
                    + "        },\n"
                    + "        \"mac\" : \"7e8f2192767af9be18e7a373c1986d9190fcaa43ad689bbb01a62dbde159338d\"\n"
                    + "    },\n"
                    + "    \"id\" : \"7654525c-17e0-4df5-94b5-c7fde752c9d2\",\n"
                    + "    \"version\" : 3\n"
                    + "}";
}
