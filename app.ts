import { Client } from "./index";
import axios from "axios";
import { request, gql } from "graphql-request";

const kastelaUrl = "http://server1.kastela.duckdns.org:3201";
const serverUrl = "https://backend1.kastela.duckdns.org";

const client = new Client(kastelaUrl, serverUrl);

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
  const secureChannels = await Promise.all(
    protections.map((protection) =>
      client.secureChannelSend(protection.id, protection.data)
    )
  );
  const query = gql`
    mutation storeUserSecure($data: UserStoreInput!) {
      store_user_secure(data: $data) {
        id
      }
    }
  `;
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
  await request(`${serverUrl}/graphql`, query, variables);
  await Promise.all(
    secureChannels.map((secureChannel) =>
      axios.post(`${serverUrl}/api/secure-channel/${secureChannel.id}/commit`)
    )
  );
  console.log("OK");
})();
