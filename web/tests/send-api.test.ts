import assert from "node:assert/strict";
import test from "node:test";
import { sendEnvelopeHTTP } from "../src/api/poll.ts";

test("HTTP fallback posts the unchanged opaque envelope and returns ack", async () => {
  const originalFetch=globalThis.fetch;const storage=Object.getOwnPropertyDescriptor(globalThis,"localStorage");
  Object.defineProperty(globalThis,"localStorage",{configurable:true,value:{getItem:()=>"token"}});
  const envelope={type:"message",id:"wire",ts:1,payload:{ciphertext:"opaque",client_id:"client"}} as never;let body="";
  globalThis.fetch=(async(input,init)=>{assert.equal(String(input),"/api/transport/send");body=String(init?.body);return new Response(JSON.stringify({type:"ack",id:"ack",ts:2,payload:{message_id:"client",state:"persisted",recipient_uin:42}}),{status:200});}) as typeof fetch;
  try{const ack=await sendEnvelopeHTTP(envelope);assert.equal(body,JSON.stringify(envelope));assert.equal(ack.type,"ack");}
  finally{globalThis.fetch=originalFetch;if(storage)Object.defineProperty(globalThis,"localStorage",storage);else Reflect.deleteProperty(globalThis,"localStorage");}
});
