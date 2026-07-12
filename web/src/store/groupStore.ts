// src/store/groupStore.ts
//
// Group list + per-group member roster. The two are kept
// in independent shapes for the same reason as
// contactStore: the group list changes slowly (one row
// per group I belong to), the member roster changes
// faster (one row per member, plus joins/parts).
//
// Step 10 introduces this store alongside the contact
// store. The two stores are intentionally separate
// because the data they hold has different update
// frequencies and different access patterns:
//   - contacts are read on every chat list render
//   - groups are read on every chat list render too,
//     but the sidebar pattern groups them together
//     ("Contacts" + "Groups" tabs) so a single store
//     would have to multiplex which list is active.
//
// Wire types in api/groups.ts are the source of truth;
// the store mirrors them with UI-only extensions
// (loading flags, error strings).

import { create } from "zustand";
import * as groupsApi from "../api/groups";
import type { GroupMemberWire, GroupWire } from "../api/groups";

interface GroupState {
  groups: GroupWire[];
  // Per-group member roster. Keyed by group_id so
  // loading one group's members does not invalidate the
  // list of groups themselves.
  members: Record<string, GroupMemberWire[]>;

  loading: boolean;
  error: string | null;

  setGroups: (groups: GroupWire[]) => void;
  addGroup: (group: GroupWire) => void;
  removeGroup: (groupId: string) => void;
  setMembers: (groupId: string, members: GroupMemberWire[]) => void;
  addMember: (groupId: string, member: GroupMemberWire) => void;
  removeMember: (groupId: string, uin: number) => void;
  updateMember: (groupId: string, member: GroupMemberWire) => void;

  // Step 10 async actions. Each one is a thin wrapper
  // over the REST client that mutates the local store
  // after a successful response.
  loadGroups: () => Promise<void>;
  createGroup: (name: string) => Promise<GroupWire>;
  loadMembers: (groupId: string) => Promise<void>;
  inviteMember: (groupId: string, uin: number) => Promise<void>;
  leaveGroup: (groupId: string, selfUin: number) => Promise<void>;
  kickMember: (groupId: string, uin: number) => Promise<void>;
  deleteGroup: (groupId: string) => Promise<void>;
}

export const useGroupStore = create<GroupState>((set, get) => ({
  groups: [],
  members: {},
  loading: false,
  error: null,

  setGroups: (groups) => set({ groups }),

  addGroup: (group) => set((s) => ({ groups: [group, ...s.groups] })),

  removeGroup: (groupId) =>
    set((s) => {
      const nextMembers = { ...s.members };
      delete nextMembers[groupId];
      return {
        groups: s.groups.filter((g) => g.group_id !== groupId),
        members: nextMembers,
      };
    }),

  setMembers: (groupId, members) =>
    set((s) => ({ members: { ...s.members, [groupId]: members } })),

  addMember: (groupId, member) =>
    set((s) => {
      const existing = s.members[groupId] ?? [];
      // Don't double-insert; an invite that's a no-op on
      // the server still triggers a loadMembers() refresh.
      if (existing.some((m) => m.uin === member.uin)) return s;
      return {
        members: {
          ...s.members,
          [groupId]: [...existing, member],
        },
      };
    }),

  removeMember: (groupId, uin) =>
    set((s) => {
      const existing = s.members[groupId] ?? [];
      return {
        members: {
          ...s.members,
          [groupId]: existing.filter((m) => m.uin !== uin),
        },
      };
    }),

  updateMember: (groupId, member) =>
    set((s) => {
      const existing = s.members[groupId] ?? [];
      const idx = existing.findIndex((m) => m.uin === member.uin);
      if (idx === -1) return s;
      const next = existing.slice();
      next[idx] = member;
      return { members: { ...s.members, [groupId]: next } };
    }),

  // --- Async actions ----------------------------------------------------

  loadGroups: async () => {
    set({ loading: true, error: null });
    try {
      const wire = await groupsApi.getGroups();
      set({ groups: wire, loading: false });
    } catch (e) {
      set({ loading: false, error: (e as Error).message });
      throw e;
    }
  },

  createGroup: async (name: string) => {
    const group = await groupsApi.createGroup(name);
    set((s) => ({ groups: [group, ...s.groups] }));
    return group;
  },

  loadMembers: async (groupId: string) => {
    try {
      const wire = await groupsApi.getGroupMembers(groupId);
      get().setMembers(groupId, wire);
    } catch (e) {
      set({ error: (e as Error).message });
      throw e;
    }
  },

  inviteMember: async (groupId: string, uin: number) => {
    // Optimistic add — show the member immediately. The
    // server-side handler will re-fetch the members
    // list on success; on failure we re-load to undo
    // any partial state.
    try {
      await groupsApi.addMember(groupId, uin);
      await get().loadMembers(groupId);
    } catch (e) {
      set({ error: (e as Error).message });
      throw e;
    }
  },

  leaveGroup: async (groupId: string, selfUin: number) => {
    // Optimistic: drop myself from the member list and
    // bump member_count by -1 in the groups list. The
    // server may then re-assign ownership — but a
    // member_count is purely a display field, so the
    // refresh that follows re-syncs it.
    const beforeGroups = get().groups;
    const beforeMembers = get().members[groupId] ?? [];
    set((s) => ({
      groups: s.groups.map((g) =>
        g.group_id === groupId ? { ...g, member_count: Math.max(0, g.member_count - 1) } : g,
      ),
      members: {
        ...s.members,
        [groupId]: beforeMembers.filter((m) => m.uin !== selfUin),
      },
    }));
    try {
      await groupsApi.leaveOrRemoveMember(groupId, selfUin);
      // If I'm the last member, the server deletes the
      // group. Re-fetch the list to discover this.
      await get().loadGroups();
    } catch (e) {
      // Roll back.
      set({ groups: beforeGroups, error: (e as Error).message });
      throw e;
    }
  },

  kickMember: async (groupId: string, uin: number) => {
    // Same shape as leaveGroup but the optimistic path
    // does not drop a "self" entry. Re-fetch on success
    // to update member_count.
    const beforeGroups = get().groups;
    const beforeMembers = get().members[groupId] ?? [];
    set((s) => ({
      groups: s.groups.map((g) =>
        g.group_id === groupId ? { ...g, member_count: Math.max(0, g.member_count - 1) } : g,
      ),
      members: {
        ...s.members,
        [groupId]: beforeMembers.filter((m) => m.uin !== uin),
      },
    }));
    try {
      await groupsApi.leaveOrRemoveMember(groupId, uin);
      await get().loadMembers(groupId);
      await get().loadGroups();
    } catch (e) {
      set({ groups: beforeGroups, error: (e as Error).message });
      throw e;
    }
  },

  deleteGroup: async (groupId: string) => {
    const before = get().groups;
    set((s) => ({ groups: s.groups.filter((g) => g.group_id !== groupId) }));
    try {
      await groupsApi.deleteGroup(groupId);
    } catch (e) {
      set({ groups: before, error: (e as Error).message });
      throw e;
    }
  },
}));
