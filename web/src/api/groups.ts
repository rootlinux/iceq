// src/api/groups.ts
//
// REST client for the group management endpoints served by
// message-service (mounted at /api/groups/* in the
// Caddyfile). All endpoints require a Bearer token; the
// standard `fetchJSON` wrapper handles auth + refresh-on-401.
//
// Wire types are colocated with each call. The store
// representation in store/groupStore.ts extends these
// with a transient UI state (loading, error) — the wire
// types are pure data, no UI concerns.

import { fetchJSON } from "./client";

// ----------------------------------------------------------------------------
// Wire types
// ----------------------------------------------------------------------------

export interface GroupWire {
  group_id: string;
  name: string;
  owner_uin: number;
  member_count: number;
  created_at: string;
  crypto_epoch: number;
}

export interface ListGroupsResponse {
  groups: GroupWire[];
}

export interface GroupMemberWire {
  uin: number;
  username: string;
  avatar_url: string;
  role: "admin" | "member";
}

export interface ListGroupMembersResponse {
  members: GroupMemberWire[];
  crypto_epoch: number;
}

export interface CreateGroupRequest {
  name: string;
}

export interface AddMemberRequest {
  uin: number;
}

// ----------------------------------------------------------------------------
// Endpoints
// ----------------------------------------------------------------------------

// createGroup creates a new group with the requesting user
// as the owner (and sole admin). The server returns the
// full GroupWire so the client can append it to the list
// without re-fetching.
//
// Errors:
//   422 NAME_LENGTH  — name not in 3..50 chars
//   401 NO_AUTH      — no Bearer token
export async function createGroup(name: string): Promise<GroupWire> {
  return fetchJSON<GroupWire>("/api/groups/", {
    method: "POST",
    body: { name } satisfies CreateGroupRequest,
  });
}

// getGroups returns every group the requesting user
// belongs to, with a member_count subquery. Sorted
// newest-first by created_at.
export async function getGroups(): Promise<GroupWire[]> {
  const resp = await fetchJSON<ListGroupsResponse>("/api/groups/", { method: "GET" });
  return resp.groups;
}

// getGroupMembers returns the membership roster of one
// group, joined with users for the public-facing fields.
// Sorted by joined_at ASC (oldest first). Caller must
// also be a member; the server returns 403 otherwise.
export async function getGroupMembersWithEpoch(groupId: string): Promise<ListGroupMembersResponse> {
  const resp = await fetchJSON<ListGroupMembersResponse>(
    `/api/groups/${encodeURIComponent(groupId)}/members`,
    { method: "GET" },
  );
  return resp;
}
export async function getGroupMembers(groupId: string): Promise<GroupMemberWire[]> { return (await getGroupMembersWithEpoch(groupId)).members; }

// addMember invites a UIN to a group. The requesting user
// must be an admin of the group; the server returns 403
// otherwise. The new member is inserted with role=member;
// the server emits a notification on
// `notification.<uin>`.
export async function addMember(groupId: string, uin: number): Promise<void> {
  await fetchJSON<void>(
    `/api/groups/${encodeURIComponent(groupId)}/members`,
    { method: "POST", body: { uin } satisfies AddMemberRequest },
  );
}

// leaveOrRemoveMember is a unified DELETE call. The
// server-side handler interprets the path uin parameter:
//
//   - If path uin == my UIN, I'm leaving. Any role is
//     allowed.
//   - If path uin is someone else, only an admin can
//     remove them.
//
// Both paths return 204 on success.
//
// When the leaving user is the owner, ownership transfers
// to the oldest remaining member. When the leaving user is
// the LAST member, the group is deleted server-side.
export async function leaveOrRemoveMember(groupId: string, uin: number): Promise<void> {
  await fetchJSON<void>(
    `/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(String(uin))}`,
    { method: "DELETE" },
  );
}

export interface SenderKeyInboxItem { sender_uin:number; ciphertext:string; msg_type:"prekey_message"|"signal_message"; distribution_id:string }
export async function putSenderKeyDistribution(groupId:string,body:{recipient_uin:number;epoch:number;distribution_id:string;ciphertext:string;msg_type:"prekey_message"|"signal_message"}):Promise<void>{
  await fetchJSON<void>(`/api/groups/${encodeURIComponent(groupId)}/sender-key-distributions`,{method:"POST",body});
}
export async function getSenderKeyDistributions(groupId:string):Promise<{epoch:number;distributions:SenderKeyInboxItem[]}>{
  return fetchJSON(`/api/groups/${encodeURIComponent(groupId)}/sender-key-distributions`,{method:"GET"});
}

// deleteGroup removes the entire group. The requesting
// user must be the group's owner; the server returns 404
// (not 403) for both "not the owner" and "doesn't exist"
// to avoid leaking group existence. group_members rows
// cascade.
export async function deleteGroup(groupId: string): Promise<void> {
  await fetchJSON<void>(
    `/api/groups/${encodeURIComponent(groupId)}`,
    { method: "DELETE" },
  );
}
