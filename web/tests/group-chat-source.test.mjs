import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(resolve(__dirname, "..", path), "utf8");

test("group chat components exist and reuse the shared chat message list/input", () => {
  assert.equal(existsSync(resolve(__dirname, "../src/components/Groups/GroupChatWindow.tsx")), true);
  assert.equal(existsSync(resolve(__dirname, "../src/components/Groups/GroupDetail.tsx")), true);

  const groupChat = read("src/components/Groups/GroupChatWindow.tsx");
  assert.match(groupChat, /<MessageList conversationId=\{`group:\$\{group\.group_id\}`\}/);
  assert.match(groupChat, /<MessageInput groupId=\{group\.group_id\}/);
  assert.match(groupChat, /historyGroup\(groupId/);
  assert.ok(groupChat.indexOf("getSenderKeyDistributions(groupId)") < groupChat.indexOf("historyGroup(groupId"), "offline sender-key inbox must hydrate before group history");
  assert.match(groupChat, /content_type: content\.content_type/);
});

test("group list opens active group conversations instead of static rows", () => {
  const groupList = read("src/components/Groups/GroupList.tsx");
  const chatStore = read("src/store/chatStore.ts");

  assert.match(chatStore, /setActiveGroupConversation/);
  assert.match(groupList, /setActiveGroupConversation\(group\)/);
  assert.match(groupList, /button/);
});

test("group detail shows members, admin badge, and member management controls", () => {
  const detail = read("src/components/Groups/GroupDetail.tsx");

  assert.match(detail, /loadMembers\(group\.group_id\)/);
  assert.match(detail, /inviteMember\(group\.group_id, parsedUin\)/);
  assert.match(detail, /kickMember\(group\.group_id, memberUin\)/);
  assert.match(detail, /member\.uin === group\.owner_uin/);
  assert.match(detail, /groups\.admin/);
});

test("message input can send group_msg frames with group conversation ids", () => {
  const input = read("src/components/Chat/MessageInput.tsx");

  assert.match(input, /groupId\?: string/);
  assert.match(input, /conversation_id: `group:\$\{groupId\}`/);
  assert.match(input, /type: "group_msg"/);
});

test("live group messages trust authenticated inner content type instead of routing metadata",()=>{
  const socket=read("src/hooks/useWebSocket.ts");
  assert.match(socket,/authenticatedGroupMessageFields\(content,p\.content_type\)/);
  assert.match(socket,/content_type: authenticatedContentType/);
  assert.doesNotMatch(socket,/content_type: p\.content_type/);
});
