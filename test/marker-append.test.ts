import assert from "node:assert/strict";
import test from "node:test";

import { appendRenameMarker } from "../src/mcp/tools.js";

test("appendRenameMarker appends the marker to a bare /rename title", () => {
  assert.equal(appendRenameMarker("/rename foo"), "/rename foo\u200b");
});

test("appendRenameMarker leaves a title that already ends with a marker", () => {
  assert.equal(appendRenameMarker("/rename foo\u200b"), "/rename foo\u200b");
});

test("appendRenameMarker requires whitespace after /rename", () => {
  assert.equal(appendRenameMarker("/renameX y"), "/renameX y");
});

test("appendRenameMarker only touches the first line", () => {
  assert.equal(appendRenameMarker("/rename foo\nbar"), "/rename foo\u200b\nbar");
});

test("appendRenameMarker puts the marker before a trailing carriage return", () => {
  assert.equal(appendRenameMarker("/rename foo\r\nbar"), "/rename foo\u200b\r\nbar");
});

test("appendRenameMarker passes other messages through", () => {
  assert.equal(appendRenameMarker("hello"), "hello");
});

test("appendRenameMarker appends after a ZWJ emoji sequence", () => {
  assert.equal(appendRenameMarker("/rename 여 \u{1F469}\u200d\u{1F4BB}"), "/rename 여 \u{1F469}\u200d\u{1F4BB}\u200b");
});
