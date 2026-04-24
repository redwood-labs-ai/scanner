// FP baseline: Template literals with SQL-like words
// These use template literals with words that contain SQL keywords
// as substrings but are NOT SQL injection vectors.

const statusMsg = `Greeting: ${userName}`;
const recordDone = `Completed at ${timestamp}`;
const lastTime = `Checked: ${formatDate(date)}`;

const pickMsg = `Picked option: ${optionValue}`;
const selectUser = `Chosen user: ${userName}`;

const removeMsg = `Cleared ${count} items from ${category}`;
const dropNote = `Skipped ${droppedFrames} frames`;
const areaMsg = `Location: ${location}`;
const addrMsg = `Sender: ${fromAddr}`;
const pointMsg = `Direction: ${direction}`;
const defaultMsg = `Defaults loaded: ${defaults}`;
