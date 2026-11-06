// Account management, on the server's command line (there is no sign-up
// page - see src/auth.js):
//
//   npm run users -- list
//   npm run users -- add <name> <admin|analyst|viewer>     asks for the password
//   npm run users -- passwd <name>                   asks for the new password
//   npm run users -- role <name> <admin|analyst|viewer>
//   npm run users -- disable <name> | enable <name>
//   npm run users -- remove <name>
//
// A password is read without echo from the terminal, or as one line from
// standard input when that is not a terminal (scripts, tests). Every change
// signs the account out everywhere. SIGNAL_CONSOLE_DATA selects the data
// directory, as for the server.
'use strict';

const auth = require('../src/auth');
const { readPassword } = require('../src/prompt');

async function main(args) {
  const [cmd, name, arg] = args;
  switch (cmd) {
    case 'list':
      for (const u of auth.listUsers()) console.log(`${u.username.padEnd(24)} ${u.role.padEnd(8)} ${u.disabled ? 'disabled' : 'active  '} created ${u.created}`);
      return;
    case 'add':
      await auth.addUser(name, arg, await readPassword(`Password for ${name} (at least ${auth.MIN_PASSWORD} characters): `));
      console.log(`added ${name} (${arg})`);
      return;
    case 'passwd':
      await auth.setPassword(name, await readPassword(`New password for ${name}: `));
      console.log(`password of ${name} changed; signed out everywhere`);
      return;
    case 'role':
      auth.setRole(name, arg);
      console.log(`${name} is now ${arg}; signed out everywhere`);
      return;
    case 'disable':
    case 'enable':
      auth.setDisabled(name, cmd === 'disable');
      console.log(`${name} ${cmd}d`);
      return;
    case 'remove':
      auth.removeUser(name);
      console.log(`removed ${name}`);
      return;
    default:
      console.log('usage: npm run users -- list | add <name> <admin|analyst|viewer> | passwd <name> | role <name> <admin|analyst|viewer> | disable <name> | enable <name> | remove <name>');
      process.exitCode = 2;
  }
}

main(process.argv.slice(2)).catch((err) => { console.error(`users: ${err.message}`); process.exitCode = 1; });
