import axios, { AxiosInstance, isAxiosError } from "axios";
import nacl from "tweetnacl";
import {
  encodeBase64,
  decodeBase64,
  decodeUTF8,
  encodeUTF8,
} from "tweetnacl-util";

/**
 * @class
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * @param {string} kastelaUrl Kastela server url
 */
export class Client {
  #axiosInstance: AxiosInstance;
  #kastelaUrl: string;

  public constructor(kastelaUrl: string) {
    this.#kastelaUrl = kastelaUrl;
    this.#axiosInstance = axios.create();
    this.#axiosInstance.interceptors.response.use((response) => {
      response.headers = Object.fromEntries(
        Object.entries(response.headers).map(([k, v]) => [
          k.toLowerCase(),
          v as string,
        ])
      );
      return response;
    });
  }

  async #request(method: string, url: URL, body?: any) {
    try {
      const { data } = await this.#axiosInstance.request({
        url: url.toString(),
        method,
        data: body,
      });
      return data;
    } catch (error: any) {
      const data = error?.response?.data;
      if (data) {
        switch (typeof data) {
          case "object":
            throw new Error(data.error);
          default:
            throw new Error(data);
        }
      } else {
        throw error;
      }
    }
  }

  /** Send encrypted protection data to server.
   * @param {string} credential secure protection credential
   * @param {any[][]} values protection data to be sent to the server. the sequence of data match the protection_id sequence on init
   * @return {Promise<{tokens: string[][]}>} token that will be stored in the database. the tokens sequence corresponds to the data sequence
   * @example
   * 	// send "123","456","789" to server
   * client.secureProtectionSend("yourCredential", [["123","456"],["789"]])
   */
  public async secureProtectionSend(
    credential: string,
    values: any[][]
  ): Promise<{ tokens: string[][] }> {
    const { publicKey: clientPublicKey, secretKey: clientPrivateKey } =
      nacl.box.keyPair();
    const { server_public_key } = await this.#request(
      "POST",
      new URL("/api/secure/protection/begin", this.#kastelaUrl),
      {
        credential,
        client_public_key: encodeBase64(clientPublicKey),
      }
    );
    const fulltexts = values.map((value) =>
      value.map((v) => {
        const plaintext = decodeUTF8(JSON.stringify(v));
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const serverPublicKey = decodeBase64(server_public_key);
        const ciphertext = nacl.box(
          plaintext,
          nonce,
          serverPublicKey,
          clientPrivateKey
        );
        const fulltext = new Uint8Array(nonce.length + ciphertext.length);
        fulltext.set(nonce);
        fulltext.set(ciphertext, nonce.length);
        return encodeBase64(fulltext);
      })
    );
    const { tokens } = await this.#request(
      "POST",
      new URL("/api/secure/protection/store", this.#kastelaUrl),
      { credential, values: fulltexts }
    );
    return { tokens };
  }

  /** Receive encrypted protection data from server.
   * @param {string} credential secure protection credential
   * @param {string[][]} tokens token to be sent to the server. the sequence of token match the protection_id sequence on init
   * @return {Promise<{values: any[][]}>} token that will be stored in the database. the tokens sequence corresponds to the data sequence
   * @example
   * 	// send "123","456","789" to server
   * client.secureProtectionReceive("yourCredential", [["foo","bar"],["baz"]])
   */
  public async secureProtectionReceive(
    credential: string,
    tokens: string[][]
  ): Promise<{ values: any[][] }> {
    const { publicKey: clientPublicKey, secretKey: clientPrivateKey } =
      nacl.box.keyPair();
    const { server_public_key } = await this.#request(
      "POST",
      new URL("/api/secure/protection/begin", this.#kastelaUrl),
      {
        credential,
        client_public_key: encodeBase64(clientPublicKey),
      }
    );
    const { values: fulltexts } = await this.#request(
      "POST",
      new URL("/api/secure/protection/fetch", this.#kastelaUrl),
      {
        credential,
        tokens,
      }
    );
    const values = fulltexts.map((v: any[]) =>
      v.map((w) => {
        const fulltext = decodeBase64(w);
        const nonce = fulltext.subarray(0, nacl.box.nonceLength);
        const ciphertext = fulltext.subarray(nacl.box.nonceLength);
        const serverPublicKey = decodeBase64(server_public_key);
        const plaintext = nacl.box.open(
          ciphertext,
          nonce,
          serverPublicKey,
          clientPrivateKey
        );
        if (!plaintext) {
          throw new Error("decryption failed");
        }
        return JSON.parse(encodeUTF8(plaintext));
      })
    );
    return { values };
  }

  /** Send encrypted vault data to server.
   * @param {string} credential secure vault credential
   * @param {any[][]} values vault data to be sent to the server. the sequence of data match the vault_id sequence on init
   * @return {Promise<{tokens: string[][]}>} token that will be stored in the database. the tokens sequence corresponds to the data sequence
   * @example
   * 	// send "123","456","789" to server
   * client.securevaultSend("yourCredential", [["123","456"],["789"]])
   */
  public async secureVaultSend(
    credential: string,
    values: any[][]
  ): Promise<{ tokens: string[][] }> {
    const { publicKey: clientPublicKey, secretKey: clientPrivateKey } =
      nacl.box.keyPair();
    const { server_public_key } = await this.#request(
      "POST",
      new URL("/api/secure/vault/begin", this.#kastelaUrl),
      {
        credential,
        client_public_key: encodeBase64(clientPublicKey),
      }
    );
    const fulltexts = values.map((value) =>
      value.map((v) => {
        const plaintext = decodeUTF8(JSON.stringify(v));
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const serverPublicKey = decodeBase64(server_public_key);
        const ciphertext = nacl.box(
          plaintext,
          nonce,
          serverPublicKey,
          clientPrivateKey
        );
        const fulltext = new Uint8Array(nonce.length + ciphertext.length);
        fulltext.set(nonce);
        fulltext.set(ciphertext, nonce.length);
        return encodeBase64(fulltext);
      })
    );
    const { tokens } = await this.#request(
      "POST",
      new URL("/api/secure/vault/store", this.#kastelaUrl),
      { credential, values: fulltexts }
    );
    return { tokens };
  }

  /** Receive encrypted vault data from server.
   * @param {string} credential secure vault credential
   * @param {string[][]} tokens token to be sent to the server. the sequence of token match the vault_id sequence on init
   * @return {Promise<{values: any[][]}>} token that will be stored in the database. the tokens sequence corresponds to the data sequence
   * @example
   * 	// send "123","456","789" to server
   * client.secureVaultReceive("yourCredential", [["foo","bar"],["baz"]])
   */
  public async secureVaultReceive(
    credential: string,
    tokens: string[][]
  ): Promise<{ values: any[][] }> {
    const { publicKey: clientPublicKey, secretKey: clientPrivateKey } =
      nacl.box.keyPair();
    const { server_public_key } = await this.#request(
      "POST",
      new URL("/api/secure/vault/begin", this.#kastelaUrl),
      {
        credential,
        client_public_key: encodeBase64(clientPublicKey),
      }
    );
    const { values: fulltexts } = await this.#request(
      "POST",
      new URL("/api/secure/vault/fetch", this.#kastelaUrl),
      {
        credential,
        tokens,
      }
    );
    const values = fulltexts.map((v: any[]) =>
      v.map((w) => {
        const fulltext = decodeBase64(w);
        const nonce = fulltext.subarray(0, nacl.box.nonceLength);
        const ciphertext = fulltext.subarray(nacl.box.nonceLength);
        const serverPublicKey = decodeBase64(server_public_key);
        const plaintext = nacl.box.open(
          ciphertext,
          nonce,
          serverPublicKey,
          clientPrivateKey
        );
        if (!plaintext) {
          throw new Error("decryption failed");
        }
        return JSON.parse(encodeUTF8(plaintext));
      })
    );
    return { values };
  }
}
