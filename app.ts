import { Client } from "./index";
import axios from "axios";
import { request, gql } from "graphql-request";

const kastelaUrl = "http://127.0.0.1:3200";
const backendUrl = "http://127.0.0.1:4000";

const client = new Client(kastelaUrl);

const protections: Array<{ id: string; data: [string] }> = [
  {
    id: "5f77f9c2-2800-4661-b479-a0791aa0eacc",
    data: ["disyam@hash.id"],
  },
  {
    id: "6980a205-db7a-4b8e-bfce-551709034cc3",
    data: ["INDONESIA"],
  },
  {
    id: "963d8305-f68c-4f9a-b6b4-d568fc3d8f78",
    data: ["1234123412341234"],
  },
  {
    id: "0c392d3c-4ec0-4e11-a5bc-d6e094c21ea0",
    data: ["123-456-7890"],
  },
];

async function store() {
  const {
    data: { credential },
  } = await axios.post(`${backendUrl}/api/secure/protection/init`, {
    operation: "WRITE",
    protection_ids: protections.map((protection) => protection.id),
    ttl: 1,
  });
  const { tokens } = await client.secureProtectionSend(
    credential,
    protections.map((protection) => protection.data)
  );
  const query = gql`
    mutation store_user_secure($data: UserStoreInput!, $credential: String!) {
      store_user_secure(data: $data, credential: $credential) {
        id
      }
    }
  `;
  const variables = {
    data: {
      id: 100,
      name: "Disyam Adityana",
      email: tokens[0][0],
      country: tokens[1][0],
      credit_card: tokens[2][0],
      phone: tokens[3][0],
    },
    credential,
  };
  console.log("store input", variables.data);
  await request(`${backendUrl}/graphql`, query, variables);
}

async function update() {
  const {
    data: { credential },
  } = await axios.post(`${backendUrl}/api/secure/protection/init`, {
    operation: "WRITE",
    protection_ids: [protections[0].id],
    ttl: 1,
  });
  const { tokens } = await client.secureProtectionSend(credential, [
    ["disyam.adityana@gmail.com"],
  ]);
  const query = gql`
    mutation update_user_secure(
      $id: Int!
      $data: UserUpdateInput!
      $credential: String!
    ) {
      update_user_secure(id: $id, data: $data, credential: $credential)
    }
  `;
  const variables = {
    id: 100,
    data: { email: tokens[0][0] },
    credential,
  };
  console.log("update input", variables.data);
  await request(`${backendUrl}/graphql`, query, variables);
}

async function get() {
  const query = gql`
    query get_user($id: Int!) {
      get_user(id: $id) {
        id
        email
        country
        credit_card
        phone
      }
    }
  `;
  const variables = {
    id: 100,
  };
  const { get_user: data } = await request(
    `${backendUrl}/graphql`,
    query,
    variables
  );
  console.log("get data", data);
}

(async () => {
  await store();
  await update();
  await get();
})();
