import axios, { AxiosInstance, isAxiosError } from "axios";
import semver from "semver";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64, decodeUTF8 } from "tweetnacl-util";

const expectedKastelaVersion = "v0.2";
const secureChannelPath = "/api/secure-channel";

/**
 * @class
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * @param {string} kastelaUrl Kastela server url
 */
export class Client {
  #axiosInstance: AxiosInstance;
  #kastelaUrl: string;
  #serverUrl: string;

  public constructor(kastelaUrl: string, serverUrl: string) {
    this.#kastelaUrl = kastelaUrl;
    this.#serverUrl = serverUrl;
    this.#axiosInstance = axios.create();
  }

  async #request(method: string, url: URL, body?: any) {
    try {
      const { data, headers } = await this.#axiosInstance.request({
        url: url.toString(),
        method,
        data: body,
      });
      const actualKastelaVersion = headers["x-kastela-version"]!;
      if (
        semver.satisfies(
          actualKastelaVersion,
          `${expectedKastelaVersion} || v0.0.0`
        )
      ) {
        return data;
      } else {
        throw new Error(
          `kastela server version mismatch, expected: ${expectedKastelaVersion}.x, actual: ${actualKastelaVersion}`
        );
      }
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

  /** Send encrypted data to server.
   * @param {string} credential secure channel credential
   * @param {any} data data to be sent to the server.
   * @return {Promise<{id: string, token: string}>} secure channel id and token that will be stored in the database.
   * @example
   * 	// send "123456" to server
   * client.secureChannelSend("yourCredential", "123456")
   */
  public async secureChannelSend(
    credential: string,
    data: any
  ): Promise<{ id: string; token: string }> {
    const { publicKey: clientPublicKey, secretKey: clientPrivateKey } =
      nacl.box.keyPair();
    const { id, server_public_key } = await this.#request(
      "POST",
      new URL(`${secureChannelPath}/begin`, this.#kastelaUrl),
      {
        credential,
        client_public_key: encodeBase64(clientPublicKey),
      }
    );
    const plaintext = decodeUTF8(String(data));
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
    const { token } = await this.#request(
      "POST",
      new URL(`${secureChannelPath}/insert`, this.#kastelaUrl),
      { credential, data: encodeBase64(fulltext) }
    );
    return { id, token };
  }
}
