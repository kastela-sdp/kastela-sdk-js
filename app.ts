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
const vaults: Array<{ id: string; data: [string] }> = [
  {
    id: "b64e2268-fca6-4605-8b5a-307a315b266d",
    data: ["1945-08-17"],
  },
];
const id = Math.floor(Date.now() / 1000);

async function store() {
  const {
    data: { credential: protectionCredential },
  } = await axios.post(`${backendUrl}/api/secure/protection/init`, {
    operation: "WRITE",
    protection_ids: protections.map((protection) => protection.id),
    ttl: 1,
  });
  const { tokens: protectionTokens } = await client.secureProtectionSend(
    protectionCredential,
    protections.map((protection) => protection.data)
  );
  const {
    data: { credential: vaultCredential },
  } = await axios.post(`${backendUrl}/api/secure/vault/init`, {
    operation: "WRITE",
    vault_ids: vaults.map((vault) => vault.id),
    ttl: 1,
  });
  const { tokens: vaultTokens } = await client.secureVaultSend(
    vaultCredential,
    vaults.map((vault) => vault.data)
  );
  const query = gql`
    mutation store_user_secure($data: UserStoreInput!, $credential: String!) {
      store_user_secure(data: $data, credential: $credential)
    }
  `;
  const variables = {
    data: {
      id,
      name: "Disyam Adityana",
      email: protectionTokens[0][0],
      country: protectionTokens[1][0],
      credit_card: protectionTokens[2][0],
      phone: protectionTokens[3][0],
      birthdate: vaultTokens[0][0],
    },
    credential: protectionCredential,
  };
  await request(`${backendUrl}/graphql`, query, variables);
  console.log("update OK");
}

async function update() {
  const {
    data: { credential: protectionCredential },
  } = await axios.post(`${backendUrl}/api/secure/protection/init`, {
    operation: "WRITE",
    protection_ids: [protections[0].id],
    ttl: 1,
  });
  const { tokens: protectionTokens } = await client.secureProtectionSend(
    protectionCredential,
    [["disyam.adityana@gmail.com"]]
  );
  const {
    data: { credential: vaultCredential },
  } = await axios.post(`${backendUrl}/api/secure/vault/init`, {
    operation: "WRITE",
    vault_ids: [vaults[0].id],
    ttl: 1,
  });
  const { tokens: vaultTokens } = await client.secureVaultSend(
    vaultCredential,
    [["2023-05-02"]]
  );
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
    id,
    data: {
      email: protectionTokens[0][0],
      birthdate: vaultTokens[0][0],
    },
    credential: protectionCredential,
  };
  await request(`${backendUrl}/graphql`, query, variables);
  console.log("store OK");
}

async function get() {
  const query = gql`
    query get_user_secure($id: Int!) {
      get_user_secure(id: $id) {
        id
        email
        country
        credit_card
        phone
        birthdate
      }
    }
  `;
  const variables = { id };
  const { get_user_secure: data } = await request(
    `${backendUrl}/graphql`,
    query,
    variables
  );
  const {
    data: { credential: protectionCredential },
  } = await axios.post(`${backendUrl}/api/secure/protection/init`, {
    operation: "READ",
    protection_ids: protections.map((protection) => protection.id),
    ttl: 1,
  });
  const protectionTokens: string[][] = [
    [data.email],
    [data.country],
    [data.credit_card],
    [data.phone],
  ];
  const { values: protectionValues } = await client.secureProtectionReceive(
    protectionCredential,
    protectionTokens
  );
  console.log("email:", protectionValues[0][0]);
  console.log("country:", protectionValues[1][0]);
  console.log("credit_card:", protectionValues[2][0]);
  console.log("phone:", protectionValues[3][0]);
  const {
    data: { credential: vaultCredential },
  } = await axios.post(`${backendUrl}/api/secure/vault/init`, {
    operation: "READ",
    vault_ids: vaults.map((vault) => vault.id),
    ttl: 1,
  });
  const vaultTokens: string[][] = [[data.birthdate]];
  const { values: vaultValues } = await client.secureVaultReceive(
    vaultCredential,
    vaultTokens
  );
  console.log("birthdate:", vaultValues[0][0]);
}

(async () => {
  await store();
  await get();
  await update();
  await get();
})();
