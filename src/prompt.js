// Questions asked in the server's own shell: the first account at start
// (server.js) and the account commands (scripts/users.js).
'use strict';

const readline = require('readline');

// ask asks one question on the terminal; hidden: the answer is not echoed.
function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = (s) => { if (s.startsWith(question)) process.stdout.write(question); }; // echo the question only
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

// readPassword prompts twice on a terminal (without echo), once otherwise -
// one line from standard input (scripts, tests).
async function readPassword(prompt) {
  if (!process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin });
    for await (const line of rl) { rl.close(); return line; }
    return '';
  }
  const first = await ask(prompt, true);
  if (first !== await ask('Again: ', true)) throw new Error('the two passwords differ');
  return first;
}

module.exports = { ask, readPassword };
