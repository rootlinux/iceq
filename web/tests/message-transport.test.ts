import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";

import { MessageTransportCoordinator, TransportInbox, markEnvelopeRetryable } from "../src/hooks/useMessageTransport.ts";
import { persistTransportEnvelope } from "../src/hooks/useWebSocket.ts";
import { claimTransportEnvelopeID, commitTransportEnvelopeID, isTransportEnvelopeCommitted, releaseTransportEnvelopeID } from "../src/lib/indexeddb.ts";
import { ApiError, ApiNetworkError } from "../src/api/client.ts";

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
		wsSend:(env)=>{ws.push(env.id);return true;},consume:async(env)=>{consumed.push(env.id);return true;},onSendFailure:()=>{},retryDelayMs:0,
	});
	coordinator.setConnected(false);await Promise.resolve();assert.equal(pollSignal?.aborted,false);
	coordinator.send({type:"message",id:"fallback",ts:1,payload:{}} as never);await Promise.resolve();await Promise.resolve();assert.deepEqual(http,["fallback"]);assert.deepEqual(consumed,["ack"]);
	coordinator.setConnected(true);assert.equal(pollSignal?.aborted,true);coordinator.send({type:"message",id:"live",ts:1,payload:{}} as never);assert.deepEqual(ws,["live"]);
	resolvePoll({cursor:"next",envelopes:[{type:"message",id:"late",ts:1,payload:{}}]});await Promise.resolve();assert.equal(consumed.includes("late"),false);
});

test("lost advanced poll response resets an invalid cursor and recovers cursorless without duplicate delivery", async () => {
  const calls: Array<string | null> = [];
  const delivered: string[] = [];
  let coordinator!: MessageTransportCoordinator;
	const suffix = `${Date.now()}-${Math.random()}`;
	const page1 = {type:"message", id:`page-1-${suffix}`, ts:1, payload:{}} as never;
	const page2 = {type:"message", id:`page-2-${suffix}`, ts:2, payload:{}} as never;
  const poll = async (cursor: string | null): Promise<{cursor:string; envelopes:any[]}> => {
    calls.push(cursor);
    if (calls.length === 1) return {cursor:"cursor-1", envelopes:[page1]};
    if (calls.length === 2) throw new ApiNetworkError("response lost after server advance");
    if (calls.length === 3) throw new ApiError("invalid", 400, "INVALID_POLL_CURSOR");
	return {cursor:"cursor-recovered", envelopes:[page1, page2]};
  };
  coordinator = new MessageTransportCoordinator({
    poll: poll as never, httpSend: async()=>page1, wsSend:()=>false,
	consume: async (env) => { if (env.id === page2.id) coordinator.setConnected(true);
	  const owner = await claimTransportEnvelopeID(env.id);
	  if (!owner) return isTransportEnvelopeCommitted(env.id);
	  delivered.push(env.id);
	  await commitTransportEnvelopeID(env.id, owner);
	  return true; },
    onSendFailure:()=>{}, retryDelayMs:0,
  });
  coordinator.setConnected(false);
  for (let i=0; i<30 && delivered.length<2; i++) await new Promise((resolve)=>setTimeout(resolve, 1));
  assert.deepEqual(calls.slice(0,4), [null, "cursor-1", "cursor-1", null]);
  assert.deepEqual(delivered, [page1.id, page2.id]);
});

test("poll cursor never authorizes server ACK before every page item durably commits", async () => {
  const calls: Array<string | null> = [];
  let releaseCommit!: (value: boolean) => void;
  const durableCommit = new Promise<boolean>((resolve) => { releaseCommit = resolve; });
  let coordinator!: MessageTransportCoordinator;
  coordinator = new MessageTransportCoordinator({
	poll: async (cursor) => {
	  calls.push(cursor);
	  if (calls.length === 1) return {cursor:"ack-token", envelopes:[{type:"message",id:"crash-window",ts:1,payload:{}} as never]};
	  coordinator.setConnected(true);
	  return new Promise(()=>{});
	},
	httpSend: async()=>({} as never), wsSend:()=>false,
	consume: async()=>durableCommit, onSendFailure:()=>{}, retryDelayMs:0,
  });
  coordinator.setConnected(false);
  await new Promise((resolve)=>setTimeout(resolve, 5));
  assert.deepEqual(calls, [null], "next poll would ACK before IndexedDB commit");
  releaseCommit(true);
  for (let i=0; i<20 && calls.length<2; i++) await new Promise((resolve)=>setTimeout(resolve, 1));
  assert.deepEqual(calls, [null, "ack-token"]);
});

test("failed durable page item retains predecessor cursor and retries without ACK", async () => {
  const calls: Array<string | null> = [];
  let coordinator!: MessageTransportCoordinator;
  coordinator = new MessageTransportCoordinator({
	poll: async (cursor) => {
	  calls.push(cursor);
	  if (calls.length === 1) return {cursor:"must-not-ack", envelopes:[{type:"message",id:"failed-item",ts:1,payload:{}} as never]};
	  coordinator.setConnected(true);
	  return new Promise(()=>{});
	},
	httpSend: async()=>({} as never), wsSend:()=>false, consume:async()=>false, onSendFailure:()=>{}, retryDelayMs:0,
  });
  coordinator.setConnected(false);
  for (let i=0; i<20 && calls.length<2; i++) await new Promise((resolve)=>setTimeout(resolve, 1));
  assert.deepEqual(calls, [null, null]);
});

test("transport logout aborts active poll and HTTP failure enters safe retry state",async()=>{
	let signal:AbortSignal|undefined;let failed="";const coordinator=new MessageTransportCoordinator({poll:async(_c,s)=>{signal=s;return new Promise(()=>{});},httpSend:async()=>{throw new Error("down")},wsSend:()=>false,consume:async()=>true,onSendFailure:(env)=>{failed=env.id},retryDelayMs:0});
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
  const owner = await claimTransportEnvelopeID(id);
	assert.ok(owner);
	await commitTransportEnvelopeID(id, owner);
	assert.equal(await isTransportEnvelopeCommitted(id), true);
  // A newly-created receive boundary uses the same IndexedDB claim.
	assert.equal(await claimTransportEnvelopeID(id), null);
});

test("concurrent WS and poll claims dispatch one stable message id", async () => {
  const id = `race-${Date.now()}-${Math.random()}`;
  const claims = await Promise.all([claimTransportEnvelopeID(id), claimTransportEnvelopeID(id)]);
	assert.equal(claims.filter(Boolean).length, 1);
});

test("expired persistent seen records are reclaimed", async () => {
  const id = `expires-${Date.now()}-${Math.random()}`;
	const firstOwner = await claimTransportEnvelopeID(id, Date.now() + 5);
	assert.ok(firstOwner);
	await commitTransportEnvelopeID(id, firstOwner);
  await new Promise((resolve) => setTimeout(resolve, 10));
	assert.ok(await claimTransportEnvelopeID(id, Date.now() + 1000));
});

test("failed real durable dispatch releases claim and remains retryable without seen commit", async () => {
	const id = `dispatch-failure-${Date.now()}-${Math.random()}`;
	let acknowledgements = 0;
	await assert.rejects(() => persistTransportEnvelope(id, undefined, async () => { throw new Error("temporary session unavailable"); }, () => { acknowledgements += 1; }));
	assert.equal(await isTransportEnvelopeCommitted(id), false);
	assert.equal(acknowledgements, 0, "WS transport_ack must follow successful durable processing");
	const owner = await claimTransportEnvelopeID(id);
	assert.ok(owner, "failed poll/WS dispatch must remain claimable for retry");
});

test("lease takeover rejects stale owner commit and release without corrupting new owner", async () => {
	const id = `lease-takeover-${Date.now()}-${Math.random()}`;
	const realNow = Date.now;
	let now = realNow();
	Date.now = () => now;
	try {
	  const staleOwner = await claimTransportEnvelopeID(id);
	  assert.ok(staleOwner);
	  now += 60_001;
	  const newOwner = await claimTransportEnvelopeID(id);
	  assert.ok(newOwner);
	  assert.notEqual(newOwner, staleOwner);
	  assert.equal(await commitTransportEnvelopeID(id, staleOwner), false);
	  assert.equal(await releaseTransportEnvelopeID(id, staleOwner), false);
	  assert.equal(await commitTransportEnvelopeID(id, newOwner), true);
	  assert.equal(await isTransportEnvelopeCommitted(id), true);
	} finally { Date.now = realNow; }
});
