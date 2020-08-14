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

import java.math.BigInteger;

import org.web3j.utils.Numeric;

/**
 * Transaction class used for signing transactions locally.<br>
 * For the specification, refer to p4 of the <a href="http://gavwood.com/paper.pdf">yellow
 * paper</a>.
 */
public class RawTransactionWithKey {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private BigInteger pubKeyX;
    private BigInteger pubKeyY;
    private BigInteger gasPremium;
    private BigInteger feeCap;

    protected RawTransactionWithKey(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {
        this(nonce, gasPrice, gasLimit, to, value, data, null, null, publicKeyX, publicKeyY);
    }

    protected RawTransactionWithKey(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger gasPremium,
            BigInteger feeCap,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        this.data = data != null ? Numeric.cleanHexPrefix(data) : null;
        this.gasPremium = gasPremium;
        this.feeCap = feeCap;
        this.pubKeyX = publicKeyX;
        this.pubKeyY = publicKeyY;
    }

    public static RawTransactionWithKey createContractTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            BigInteger value,
            String init,
            BigInteger publicKeyX,
            BigInteger publicKeyY){

        return new RawTransactionWithKey(nonce, gasPrice, gasLimit, "", value, init, publicKeyX, publicKeyY);
    }

    public static RawTransactionWithKey createEtherTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {

        return new RawTransactionWithKey(nonce, gasPrice, gasLimit, to, value, "", publicKeyX, publicKeyY);
    }

    public static RawTransactionWithKey createEtherTransaction(
            BigInteger nonce,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            BigInteger gasPremium,
            BigInteger feeCap,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {
        return new RawTransactionWithKey(nonce, null, gasLimit, to, value, "", gasPremium, feeCap, publicKeyX, publicKeyY);
    }

    public static RawTransactionWithKey createTransaction(
            BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, String data, BigInteger publicKeyX, BigInteger publicKeyY) {
        return createTransaction(nonce, gasPrice, gasLimit, to, BigInteger.ZERO, data, publicKeyX, publicKeyY);
    }

    public static RawTransactionWithKey createTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {

        return new RawTransactionWithKey(nonce, gasPrice, gasLimit, to, value, data, publicKeyX, publicKeyY);
    }

    public static RawTransactionWithKey createTransaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger gasPremium,
            BigInteger feeCap,
            BigInteger publicKeyX,
            BigInteger publicKeyY) {

        return new RawTransactionWithKey(nonce, gasPrice, gasLimit, to, value, data, gasPremium, feeCap, publicKeyX, publicKeyY);
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public BigInteger getGasLimit() {
        return gasLimit;
    }

    public String getTo() {
        return to;
    }

    public BigInteger getValue() {
        return value;
    }

    public String getData() {
        return data;
    }

    public BigInteger getPublicKeyX() {
        return pubKeyX;
    }
    public BigInteger getPublicKeyY() {
        return pubKeyY;
    }

    public BigInteger getGasPremium() {
        return gasPremium;
    }

    public BigInteger getFeeCap() {
        return feeCap;
    }

    public boolean isLegacyTransaction() {
        return gasPrice != null && gasPremium == null && feeCap == null;
    }

    public boolean isEIP1559Transaction() {
        return gasPrice == null && gasPremium != null && feeCap != null;
    }
}
