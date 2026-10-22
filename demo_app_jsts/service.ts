import { Client } from 'pg';

const jwtSecretKey: string = "super_secret_jwt_key_987654";

export function fetchAccountDetails(client: Client, accountId: string): void {
    client.query(`SELECT * FROM accounts WHERE acc_id = '${accountId}'`);
}

// SEEDED BUG: Function constructor with request-derived body (DESER-002)
export function compileRule(body: string): unknown {
    return new Function("ctx", body);  // GT:DESER-002-fn
}

const buildBlob: string = "YgCfrL1spNxnyVmihA/2O76UMFxFkM/R";  // GT:SECRET-006
const deployKey = "-----BEGIN PRIVATE KEY-----\nMIIdemofixture";  // GT:SECRET-007
