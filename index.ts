import axios, { AxiosInstance, isAxiosError } from "axios";
import semver from "semver";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64, decodeUTF8 } from "tweetnacl-util";

const expectedKastelaVersion = "v0.0";
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

  public constructor(kastelaUrl: string) {
    this.#kastelaUrl = kastelaUrl;
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

  public generateKeyPair() {
    const keyPair = nacl.box.keyPair();
    const publicKey = encodeBase64(keyPair.publicKey);
    const privateKey = encodeBase64(keyPair.secretKey);
    return { publicKey, privateKey };
  }

  /** Send encrypted data to server.
   * @param {string} secureChannelId
   * @param {string} serverPublicKey servern public key
   * @param {any} data data to be sent to the server.
   * @return {Promise<string>} token that will be stored in the database.
   * @example
   * 	// send "123456" to server
   * client.secureInsert("yoursecureChannelId", "123456")
   */
  public async secureInsert(
    secureChannelId: string,
    serverPublicKey: string,
    clientPrivateKey: string,
    data: any
  ): Promise<string> {
    const cliPriv = decodeBase64(clientPrivateKey);
    const servPub = decodeBase64(serverPublicKey);
    const plaintext = decodeUTF8(String(data));
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const ciphertext = nacl.box(plaintext, nonce, servPub, cliPriv);
    const fulltext = new Uint8Array(nonce.length + ciphertext.length);
    fulltext.set(nonce);
    fulltext.set(ciphertext, nonce.length);
    const { token } = await this.#request(
      "POST",
      new URL(
        `${secureChannelPath}/${secureChannelId}/insert`,
        this.#kastelaUrl
      ),
      fulltext
    );
    return token;
  }
}
