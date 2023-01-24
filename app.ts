import { Client } from "./index";
import axios from "axios";
import { request, gql } from "graphql-request";

const kastelaUrl = "http://server1.kastela.duckdns.org:3201";
const serverUrl = "http://127.0.0.1:4000";

const client = new Client(kastelaUrl);

const protections: Array<{ id: string; data: string }> = [
  {
    id: "5f77f9c2-2800-4661-b479-a0791aa0eacc",
    data: "disyam@hash.id",
  },
  {
    id: "6980a205-db7a-4b8e-bfce-551709034cc3",
    data: "INDONESIA",
  },
  {
    id: "963d8305-f68c-4f9a-b6b4-d568fc3d8f78",
    data: "1234123412341234",
  },
  {
    id: "0c392d3c-4ec0-4e11-a5bc-d6e094c21ea0",
    data: "123-466-7890",
  },
];

(async () => {
  console.log(1);
  const secureChannels = await Promise.all(
    protections.map(async (protection) => {
      const { publicKey, privateKey } = client.generateKeyPair();
      const {
        data: { id, server_public_key },
      } = await axios.post(`${serverUrl}/api/secure-channel/begin`, {
        protection_id: protection.id,
        client_public_key: publicKey,
        ttl: 1,
      });
      const token = await client.secureInsert(
        id,
        server_public_key,
        privateKey,
        protection.data
      );
      return { id, token };
    })
  );
  console.log(2);
  const query = gql`
    mutation storeUserSecure($data: UserStoreData!) {
      store_user_secure(data: $data) {
        id
      }
    }
  `;
  console.log(3);
  const variables = {
    data: {
      id: 100,
      name: "Disyam Adityana",
      email: secureChannels[0].token,
      country: secureChannels[1].token,
      credit_card: secureChannels[2].token,
      phone: secureChannels[3].token,
    },
  };
  console.log("data", variables.data);
  await request("http://127.0.0.1:4000/graphql", query, variables);
  await Promise.all(
    secureChannels.map((result) =>
      axios.post(`${serverUrl}/api/secure-channel/${result.id}/commit`)
    )
  );
  console.log(4);
  console.log("OK");
})();
