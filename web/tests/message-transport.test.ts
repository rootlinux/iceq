import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";

import { MessageTransportCoordinator, TransportInbox, markEnvelopeRetryable } from "../src/hooks/useMessageTransport.ts";
import { claimTransportEnvelopeID, commitTransportEnvelopeID, isTransportEnvelopeCommitted } from "../src/lib/indexeddb.ts";

const raw = (id: string) => JSON.stringify({ type: "message", id, ts: 1, payload: { ciphertext: "opaque" } });

test("WS and poll use one parser/callback and suppress duplicate envelope IDs", () => {
  const delivered: string[] = [];
  const inbox = new TransportInbox((env, source) => delivered.push(`${source}:${env.id}`), 3);
  assert.equal(inbox.consume(raw("one"), "ws"), true);
  assert.equal(inbox.consume(raw("one"), "poll"), false);
  assert.equal(inbox.consume(raw("two"), "poll"), true);
  assert.deepEqual(delivered, ["ws:one", "poll:two"]);
});

test("transport lifecycle falls back for receive and send then promotes to WS and aborts poll", async()=>{
	let resolvePoll!:(value:{cursor:string;envelopes:any[]})=>void;let pollSignal:AbortSignal|undefined;const consumed:string[]=[];const http:string[]=[];const ws:string[]=[];
	const coordinator=new MessageTransportCoordinator({
		poll:async(_cursor,signal)=>{pollSignal=signal;return new Promise(resolve=>{resolvePoll=resolve;});},
		httpSend:async(env)=>{http.push(env.id);return {type:"ack",id:"ack",ts:2,payload:{}} as never;},
		wsSend:(env)=>{ws.push(env.id);return true;},consume:(env)=>{consumed.push(env.id);},onSendFailure:()=>{},retryDelayMs:0,
	});
	coordinator.setConnected(false);await Promise.resolve();assert.equal(pollSignal?.aborted,false);
	coordinator.send({type:"message",id:"fallback",ts:1,payload:{}} as never);await Promise.resolve();await Promise.resolve();assert.deepEqual(http,["fallback"]);assert.deepEqual(consumed,["ack"]);
	coordinator.setConnected(true);assert.equal(pollSignal?.aborted,true);coordinator.send({type:"message",id:"live",ts:1,payload:{}} as never);assert.deepEqual(ws,["live"]);
	resolvePoll({cursor:"next",envelopes:[{type:"message",id:"late",ts:1,payload:{}}]});await Promise.resolve();assert.equal(consumed.includes("late"),false);
});

test("transport logout aborts active poll and HTTP failure enters safe retry state",async()=>{
	let signal:AbortSignal|undefined;let failed="";const coordinator=new MessageTransportCoordinator({poll:async(_c,s)=>{signal=s;return new Promise(()=>{});},httpSend:async()=>{throw new Error("down")},wsSend:()=>false,consume:()=>{},onSendFailure:(env)=>{failed=env.id},retryDelayMs:0});
	coordinator.setConnected(false);await Promise.resolve();coordinator.send({type:"message",id:"retry",ts:1,payload:{}} as never);await Promise.resolve();await Promise.resolve();assert.equal(failed,"retry");coordinator.stop();assert.equal(signal?.aborted,true);
});

test("HTTP fallback failure marks the matching optimistic message retryable", () => {
  const state = { "dm:7:42": [{ id: "client-1", state: "sending" }, { id: "other", state: "sending" }] };
  const next = markEnvelopeRetryable(state, { type:"message", id:"wire", ts:1, payload:{client_id:"client-1"} } as never);
  assert.equal(next["dm:7:42"]?.[0]?.state, "failed");
  assert.equal(next["dm:7:42"]?.[1]?.state, "sending");
});

test("invalid envelopes never reach transport callbacks", () => {
  let calls = 0;
  const inbox = new TransportInbox(() => { calls += 1; });
  assert.equal(inbox.consume("not-json", "poll"), false);
  assert.equal(calls, 0);
});

test("dedupe memory is bounded and evicts oldest IDs", () => {
  const delivered: string[] = [];
  const inbox = new TransportInbox((env) => delivered.push(env.id), 2);
  inbox.consume(raw("one"), "ws"); inbox.consume(raw("two"), "poll"); inbox.consume(raw("three"), "poll");
  assert.equal(inbox.consume(raw("one"), "ws"), true);
  assert.deepEqual(delivered, ["one", "two", "three", "one"]);
});

test("persistent transport seen survives a browser inbox reload", async () => {
  const id = `reload-${Date.now()}-${Math.random()}`;
  assert.equal(await claimTransportEnvelopeID(id), true);
  await commitTransportEnvelopeID(id);
	assert.equal(await isTransportEnvelopeCommitted(id), true);
  // A newly-created receive boundary uses the same IndexedDB claim.
  assert.equal(await claimTransportEnvelopeID(id), false);
});

test("concurrent WS and poll claims dispatch one stable message id", async () => {
  const id = `race-${Date.now()}-${Math.random()}`;
  const claims = await Promise.all([claimTransportEnvelopeID(id), claimTransportEnvelopeID(id)]);
  assert.equal(claims.filter(Boolean).length, 1);
});

test("expired persistent seen records are reclaimed", async () => {
  const id = `expires-${Date.now()}-${Math.random()}`;
  assert.equal(await claimTransportEnvelopeID(id, Date.now() + 5), true);
  await commitTransportEnvelopeID(id);
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(await claimTransportEnvelopeID(id, Date.now() + 1000), true);
});
