import axios, { AxiosInstance, isAxiosError } from "axios";
import semver from "semver";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64, decodeUTF8 } from "tweetnacl-util";

const expectedKastelaVersion = "v0.2";

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

  /** Send encrypted protection data to server.
   * @param {string} credential secure protection credential
   * @param {any[][]} data protection data to be sent to the server. the sequence of data match the protection_id sequence on init
   * @return {Promise<{tokens: string[][]}>} token that will be stored in the database. the tokens sequence corresponds to the data sequence
   * @example
   * 	// send "123","456","789" to server
   * client.secureProtectionSend("yourCredential", [["123","456"],["789"]])
   */
  public async secureProtectionSend(
    credential: string,
    data: any[][]
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
    const fulltexts = data.map((values) =>
      values.map((value) => {
        const plaintext = decodeUTF8(String(value));
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
      new URL("/api/secure/protection/insert", this.#kastelaUrl),
      { credential, data: fulltexts }
    );
    return { tokens };
  }
}
